namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using System.Security.Claims;
using System.Text.Encodings.Web;

/// <summary>
/// Authentication handler for the ApiKey scheme. Reads the credential from a single
/// source determined by <see cref="ApiKeyAuthenticationOptions.Transport"/> — either
/// <c>Authorization: Bearer</c> or a configured custom header — resolves the matching
/// client via <see cref="IApiKeyClientResolver"/>, and emits the
/// <see cref="ClaimsPrincipal"/> for downstream authorization.
/// </summary>
/// <remarks>
/// <para>
/// One handler instance per ASP.NET scheme. The scheme name (carried in
/// <see cref="AuthenticationTicket.AuthenticationScheme"/>) discriminates which
/// <c>(Provider, Transport)</c> tuple authenticated the request — no
/// <c>auth_scheme</c> claim side-channel. Multi-scheme model.
/// </para>
/// <para>
/// Bearer-prefix disambiguation has already happened in the selector by the time
/// the handler runs. The handler strips the configured prefix (if any) for
/// consistency before invoking the resolver.
/// </para>
/// </remarks>
internal sealed class ApiKeyAuthenticationHandler(
	IOptionsMonitor<ApiKeyAuthenticationOptions> options,
	ILoggerFactory logger,
	UrlEncoder encoder,
	IApiKeyClientResolver clientResolver,
	IApiKeyValidator validator,
	IApiKeyDenylist denylist,
	ApiKeyRevocationReadiness revocationReadiness
) : AuthenticationHandler<ApiKeyAuthenticationOptions>(
		options,
		logger,
		encoder) {

	private const string BearerPrefix = "Bearer ";

	/// <summary>A stable protection-space label for the <c>WWW-Authenticate</c> realm — never the internal
	/// scheme name (which would leak the <c>ApiKey:{header}</c> transport label).</summary>
	private const string ChallengeRealm = "ApiKey";

	/// <summary>
	/// Claim types the handler emits itself from the resolved client's first-class fields. A custom
	/// <see cref="ApiKeyClient.Claims"/> entry for one of these is dropped (with a warning) so a
	/// resolver / store cannot shadow identity, role, scope, or the credential-type marker an
	/// authorization policy relies on (SessionTicket got the same guard as M-2).
	/// </summary>
	private static readonly HashSet<string> ReservedClaimTypes = new(StringComparer.OrdinalIgnoreCase) {
		ClaimTypes.NameIdentifier,
		ClaimTypes.Name,
		ClaimTypes.Role,
		"client_type",
		"scope",
	};

	private bool _badRequest;
	private bool _revocationUnavailable;
	private bool _transportNotAccepted;
	private bool _credentialPresented;

	/// <inheritdoc/>
	protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {

		// Reset per-invocation state (the handler instance may be reused within a request).
		this._badRequest = false;
		this._revocationUnavailable = false;
		this._transportNotAccepted = false;
		this._credentialPresented = false;

		var transport = this.Options.Transport;
		string? providedKey;
		string headerName;

		if (transport == CredentialTransport.BearerAuthorizationHeader) {
			providedKey = ExtractBearerToken(this.Request.Headers.Authorization);
			if (providedKey is null) {
				return AuthenticateResult.NoResult();
			}

			if (!string.IsNullOrEmpty(this.Options.BearerPrefix)
				&& providedKey.StartsWith(this.Options.BearerPrefix, StringComparison.Ordinal)) {
				providedKey = providedKey[this.Options.BearerPrefix.Length..];
			}

			headerName = "Authorization";
		} else if (transport == CredentialTransport.CustomHeader) {
			if (string.IsNullOrWhiteSpace(this.Options.HeaderName)
				|| !this.Request.Headers.TryGetValue(this.Options.HeaderName, out var values)) {
				return AuthenticateResult.NoResult();
			}

			providedKey = values.FirstOrDefault();
			if (string.IsNullOrWhiteSpace(providedKey)) {
				return AuthenticateResult.NoResult();
			}

			headerName = this.Options.HeaderName;
		} else {
			return AuthenticateResult.Fail($"Unsupported ApiKey transport: {transport}");
		}

		// A credential for this scheme was presented (vs. the NoResult paths above) — used to scope the 401
		// challenge to error="invalid_token" only when a token was actually supplied (RFC 6750 §3; L3).
		this._credentialPresented = true;

		// Reject multi-valued credential / routing headers (defense-in-depth: an upstream proxy keying on a
		// different occurrence than this handler is the classic smuggling-disagreement shape; L2). 400.
		if (HasMultipleValues(this.Request.Headers, headerName)
			|| HasMultipleValues(this.Request.Headers, ApiKeyHeaders.Source)
			|| HasMultipleValues(this.Request.Headers, ApiKeyHeaders.ClientId)) {
			this._badRequest = true;
			return AuthenticateResult.Fail("Duplicate credential or routing header.");
		}

		var requestedSource = this.Request.Headers.TryGetValue(ApiKeyHeaders.Source, out var sourceValues)
			? sourceValues.FirstOrDefault()
			: null;
		if (string.IsNullOrWhiteSpace(requestedSource)) {
			requestedSource = null;
		}

		var context = this.BuildLookupContext(transport, headerName, requestedSource);

		// Revocation gate — enforced HERE, on the handler, the one chokepoint every credential passes
		// through, so it holds regardless of which IApiKeyClientResolver is registered (an app that
		// re-registers IApiKeyClientResolver cannot disable it). Fail closed BEFORE evaluating any credential
		// when the denylist is not authoritative: either boot hydration is incomplete / faulted (with
		// AllowFaultedDenylist off), OR the denylist has saturated and had to refuse a revocation (N18) — in
		// both cases a revoked credential might slip through, so we deny rather than risk honoring one. The
		// challenge maps this to a 503 (retry), not a 401 — the credential was never judged.
		if (!revocationReadiness.IsReady || !denylist.IsAuthoritative) {
			if (this.Logger.IsEnabled(LogLevel.Warning)) {
				this.Logger.LogWarning(
					"ApiKey revocation denylist is not authoritative (ready={Ready}, authoritative={Authoritative}); " +
					"failing authentication closed (503).", revocationReadiness.IsReady, denylist.IsAuthoritative);
			}
			this._revocationUnavailable = true;
			return AuthenticateResult.Fail("API key revocation state is temporarily unavailable");
		}

		var result = await clientResolver.ResolveAsync(
			providedKey,
			context,
			this.Context.RequestAborted);

		if (result.Outcome is ApiKeyResolveOutcome.MissingRoutingSignal or ApiKeyResolveOutcome.MissingClientIndex) {
			// Missing a required routing/index header → non-descript 400 (see HandleChallengeAsync).
			// Never a blind scan of expensive sources, never an enumeration of valid sources.
			this._badRequest = true;
			return AuthenticateResult.Fail(result.FailureReason ?? "Bad request");
		}

		if (result.Outcome == ApiKeyResolveOutcome.RevocationUnavailable) {
			// Denylist not authoritative → fail closed with a 503 (retry), not a 401: the credential was
			// never evaluated, so this is not a credential rejection (see HandleChallengeAsync).
			this._revocationUnavailable = true;
			return AuthenticateResult.Fail(result.FailureReason ?? "Service unavailable");
		}

		if (!result.IsSuccess || result.Client is null) {
			if (this.Logger.IsEnabled(LogLevel.Warning)) {
				this.Logger.LogWarning(
					"API key validation failed for transport {Transport}: {Reason}",
					transport,
					result.FailureReason ?? "Unknown");
			}
			return AuthenticateResult.Fail(result.FailureReason ?? "Invalid API key");
		}

		var client = result.Client;

		// Fail closed on an anomalous identity: a success must carry a usable credential id, or the
		// revocation and authorization decisions below would operate on a blank subject (L4). A resolver
		// (including the framework's own dynamic base over a NULL store column) must not authenticate a
		// principal the denylist can never name.
		if (string.IsNullOrWhiteSpace(client.ClientId)) {
			if (this.Logger.IsEnabled(LogLevel.Warning)) {
				this.Logger.LogWarning("API key resolved with an empty client id; rejecting (fail closed).");
			}
			return AuthenticateResult.Fail("Invalid API key");
		}

		// Revocation is enforced HERE, after the resolve, on the non-replaceable handler — so a revoked
		// credential is rejected regardless of which resolver ran and even within a resolver's cache TTL (N8).
		if (denylist.IsRevoked(client.ClientId)) {
			if (this.Logger.IsEnabled(LogLevel.Warning)) {
				this.Logger.LogWarning("API key for client {ClientId} is revoked.", client.ClientId);
			}
			return AuthenticateResult.Fail("Invalid API key");
		}

		// Expiry / cryptoperiod is enforced HERE too — not only inside the optional DynamicApiKeyClientResolver
		// base class — so a custom IApiKeyClientResolver, a configured (Form-1) key, or a cache hit replaying a
		// once-valid client cannot authenticate an expired or over-age credential (N3/N7, subsumes the cache
		// expiry bypass M3). Honors AllowExpiredKeys / RequireExpiry / grace via the validator.
		if (validator.IsExpired(client.ExpiresAt) || validator.IsBeyondMaxAge(client.CreatedAt, client.MaxKeyAge)) {
			if (this.Logger.IsEnabled(LogLevel.Warning)) {
				this.Logger.LogWarning(
					"API key for client {ClientId} is expired or beyond its maximum age.", client.ClientId);
			}
			return AuthenticateResult.Fail("Invalid API key");
		}

		if (!client.AcceptedTransports.HasFlag(transport)) {
			if (this.Logger.IsEnabled(LogLevel.Warning)) {
				this.Logger.LogWarning(
					"API key for client {ClientId} presented via {Transport}, but client accepts only {AcceptedTransports}",
					client.ClientId,
					transport,
					client.AcceptedTransports);
			}
			// The credential authenticated; refusing the transport is an authorization decision, not a
			// failure to authenticate — surface it as a 403, not a 401 re-auth challenge the client cannot
			// act on (RFC 9110 §15.5.4; N5).
			this._transportNotAccepted = true;
			return AuthenticateResult.Fail("Credential presented via an unaccepted transport.");
		}

		var claims = new List<Claim> {
			new(ClaimTypes.NameIdentifier, client.ClientId),
			new(ClaimTypes.Name, client.ClientName),
			new("client_type", "api_key")
		};

		// Roles / scopes from a (semi-trusted) store are de-duplicated and screened for control characters
		// before projection, so a malformed/hostile store row can neither bloat the principal with repeats
		// nor smuggle CR/LF into a downstream sink that re-emits a claim value (N13).
		foreach (var role in client.Roles.Distinct(StringComparer.Ordinal)) {
			if (IsSafeClaimValue(role)) {
				claims.Add(new Claim(ClaimTypes.Role, role));
			} else {
				this.WarnUnsafeClaim(client.ClientId, ClaimTypes.Role);
			}
		}

		foreach (var scope in client.Scopes.Distinct(StringComparer.Ordinal)) {
			if (IsSafeClaimValue(scope)) {
				claims.Add(new Claim("scope", scope));
			} else {
				this.WarnUnsafeClaim(client.ClientId, "scope");
			}
		}

		if (client.Claims is not null) {
			foreach (var (claimType, claimValue) in client.Claims) {
				if (ReservedClaimTypes.Contains(claimType)) {
					// A custom claim must never shadow a framework claim the handler emits — dropping it
					// keeps identity/role/scope/client_type authoritative for authorization decisions.
					if (this.Logger.IsEnabled(LogLevel.Warning)) {
						this.Logger.LogWarning(
							"API key client {ClientId} declared a reserved claim '{ClaimType}'; ignoring it.",
							client.ClientId,
							claimType);
					}
					continue;
				}
				if (!IsSafeClaimValue(claimValue)) {
					this.WarnUnsafeClaim(client.ClientId, claimType);
					continue;
				}
				claims.Add(new Claim(claimType, claimValue));
			}
		}

		var identity = new ClaimsIdentity(claims, this.Scheme.Name);
		var principal = new ClaimsPrincipal(identity);
		var ticket = new AuthenticationTicket(principal, this.Scheme.Name);

		if (this.Logger.IsEnabled(LogLevel.Debug)) {
			this.Logger.LogDebug(
				"API key authenticated for client {ClientId} ({ClientName}) via {Transport} on scheme {Scheme}",
				client.ClientId,
				client.ClientName,
				transport,
				this.Scheme.Name);
		}

		return AuthenticateResult.Success(ticket);
	}

	/// <inheritdoc/>
	protected override Task HandleChallengeAsync(AuthenticationProperties properties) {
		if (this._badRequest) {
			// Non-descript 400: no WWW-Authenticate, nothing that enumerates valid sources (ADR-0020 §5/§6).
			this.Response.StatusCode = 400;
			return Task.CompletedTask;
		}

		if (this._revocationUnavailable) {
			// Fail closed, but retryable: the denylist is not authoritative yet (ADR-0020 §8). No
			// WWW-Authenticate — this is not a credential challenge.
			this.Response.StatusCode = 503;
			this.Response.Headers.RetryAfter = "5";
			return Task.CompletedTask;
		}

		if (this._transportNotAccepted) {
			// A valid credential on an unaccepted transport is an authorization refusal, not a missing
			// credential — 403, no WWW-Authenticate (the same key on the same transport would fail again; N5).
			this.Response.StatusCode = 403;
			return Task.CompletedTask;
		}

		this.Response.StatusCode = 401;

		// Only the Bearer transport has a standard challenge (RFC 6750). A custom-header scheme has no
		// registered HTTP auth-scheme to advertise; emitting `Bearer` would misdirect a conformant client to
		// a transport this scheme never reads, so we send no WWW-Authenticate for it (L3). For Bearer,
		// error="invalid_token" is added only when a credential was actually presented and rejected
		// (RFC 6750 §3) — never echoing the failure reason (the non-oracle posture is preserved).
		if (this.Options.Transport == CredentialTransport.BearerAuthorizationHeader) {
			this.Response.Headers.WWWAuthenticate = this._credentialPresented
				? $"Bearer realm=\"{ChallengeRealm}\", error=\"invalid_token\""
				: $"Bearer realm=\"{ChallengeRealm}\"";
		}

		return Task.CompletedTask;
	}

	private static bool HasMultipleValues(IHeaderDictionary headers, string name) =>
		headers.TryGetValue(name, out var values) && values.Count > 1;

	/// <summary>
	/// Whether a claim value is safe to project — rejecting C0/C1 control characters (CR/LF/NUL/…) that
	/// could corrupt a downstream sink re-emitting it (audit record, header echo, non-structured log).
	/// RFC 9110 §5.5. Empty values are harmless.
	/// </summary>
	private static bool IsSafeClaimValue(string? value) {
		if (string.IsNullOrEmpty(value)) {
			return true;
		}
		foreach (var c in value) {
			if (char.IsControl(c)) {
				return false;
			}
		}
		return true;
	}

	private void WarnUnsafeClaim(string clientId, string claimType) {
		if (this.Logger.IsEnabled(LogLevel.Warning)) {
			this.Logger.LogWarning(
				"API key client {ClientId} supplied claim '{ClaimType}' with an unsafe (control-character) value; dropping it.",
				clientId, claimType);
		}
	}

	/// <inheritdoc/>
	protected override Task HandleForbiddenAsync(AuthenticationProperties properties) {
		this.Response.StatusCode = 403;
		return Task.CompletedTask;
	}

	private static string? ExtractBearerToken(Microsoft.Extensions.Primitives.StringValues authHeader) {
		var value = authHeader.FirstOrDefault();
		if (string.IsNullOrWhiteSpace(value)) {
			return null;
		}
		if (!value.StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase)) {
			return null;
		}
		var token = value[BearerPrefix.Length..].Trim();
		return string.IsNullOrEmpty(token) ? null : token;
	}

	private ApiKeyLookupContext BuildLookupContext(
		CredentialTransport transport,
		string credentialHeader,
		string? requestedSource) {

		var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

		foreach (var header in this.Request.Headers) {
			if (string.Equals(header.Key, credentialHeader, StringComparison.OrdinalIgnoreCase)) {
				continue;
			}
			var value = header.Value.FirstOrDefault();
			if (!string.IsNullOrEmpty(value)) {
				headers[header.Key] = value;
			}
		}

		return new ApiKeyLookupContext(transport, credentialHeader, headers, requestedSource);
	}

}
