namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Authentication;
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
public class ApiKeyAuthenticationHandler(
	IOptionsMonitor<ApiKeyAuthenticationOptions> options,
	ILoggerFactory logger,
	UrlEncoder encoder,
	IApiKeyClientResolver clientResolver
) : AuthenticationHandler<ApiKeyAuthenticationOptions>(
		options,
		logger,
		encoder) {

	private const string BearerPrefix = "Bearer ";

	/// <inheritdoc/>
	protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {

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

		var context = this.BuildLookupContext(transport, headerName);

		var result = await clientResolver.ResolveAsync(
			providedKey,
			context,
			this.Context.RequestAborted);

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

		if (!client.AcceptedTransports.HasFlag(transport)) {
			if (this.Logger.IsEnabled(LogLevel.Warning)) {
				this.Logger.LogWarning(
					"API key for client {ClientId} presented via {Transport}, but client accepts only {AcceptedTransports}",
					client.ClientId,
					transport,
					client.AcceptedTransports);
			}
			return AuthenticateResult.Fail("Credential presented via an unaccepted transport.");
		}

		var claims = new List<Claim> {
			new(ClaimTypes.NameIdentifier, client.ClientId),
			new(ClaimTypes.Name, client.ClientName),
			new("client_type", "api_key")
		};

		foreach (var role in client.Roles) {
			claims.Add(new Claim(ClaimTypes.Role, role));
		}

		if (client.Claims is not null) {
			foreach (var (claimType, claimValue) in client.Claims) {
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
		this.Response.StatusCode = 401;
		this.Response.Headers.WWWAuthenticate = $"Bearer realm=\"{this.Scheme.Name}\"";
		return Task.CompletedTask;
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
		string credentialHeader) {

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

		return new ApiKeyLookupContext(transport, credentialHeader, headers);
	}

}
