namespace Cirreum.Authentication.ApiKey.Tests;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

/// <summary>
/// Handler-level proofs for the ApiKey scheme: the fail-closed posture (no 500s, no oracle), the
/// reserved-claim guard (A7), and the status mapping for the missing-routing-signal (400) and
/// revocation-unavailable (503) outcomes versus an ordinary credential rejection (401).
/// </summary>
public sealed class ApiKeyAuthenticationHandlerTests {

	private const string Scheme = "ApiKey:Bearer";

	private static IApiKeyClientResolver Resolver(ApiKeyResolveResult result) =>
		new TestResolvers.Stub(result);

	private static async Task<(AuthenticateResult Result, HttpContext Context, ApiKeyAuthenticationHandler Handler)>
		AuthenticateAsync(
			IApiKeyClientResolver resolver,
			string? authorization = "Bearer the-presented-key",
			CredentialTransport transport = CredentialTransport.BearerAuthorizationHeader,
			IApiKeyDenylist? denylist = null,
			ApiKeyRevocationReadiness? readiness = null,
			ApiKeyValidationOptions? validation = null,
			string? customHeaderName = null,
			string? customHeaderValue = null,
			string[]? authorizationValues = null) {

		var options = new ApiKeyAuthenticationOptions { Transport = transport };
		if (customHeaderName is not null) {
			options.HeaderName = customHeaderName;
		}
		var monitor = Substitute.For<IOptionsMonitor<ApiKeyAuthenticationOptions>>();
		monitor.Get(Arg.Any<string>()).Returns(options);

		var validator = new DefaultApiKeyValidator(
			Options.Create(validation ?? new ApiKeyValidationOptions()), []);
		var denyList = denylist ?? new ApiKeyDenylist(
			Options.Create(new ApiKeyRevocationOptions()),
			Options.Create(new ApiKeyValidationOptions()),
			NullLogger<ApiKeyDenylist>.Instance);
		var ready = readiness ?? ReadyReadiness();

		var handler = new ApiKeyAuthenticationHandler(
			monitor, NullLoggerFactory.Instance, UrlEncoder.Default, resolver, validator, denyList, ready);

		var context = new DefaultHttpContext { RequestServices = new ServiceCollection().BuildServiceProvider() };
		context.Request.Method = "GET";
		if (authorizationValues is not null) {
			context.Request.Headers.Authorization = new Microsoft.Extensions.Primitives.StringValues(authorizationValues);
		} else if (authorization is not null) {
			context.Request.Headers.Authorization = authorization;
		}
		if (customHeaderName is not null && customHeaderValue is not null) {
			context.Request.Headers[customHeaderName] = customHeaderValue;
		}

		var scheme = new AuthenticationScheme(Scheme, Scheme, typeof(ApiKeyAuthenticationHandler));
		await handler.InitializeAsync(scheme, context);
		return (await handler.AuthenticateAsync(), context, handler);
	}

	private static ApiKeyRevocationReadiness ReadyReadiness() {
		var r = new ApiKeyRevocationReadiness();
		r.MarkReady();
		return r;
	}

	private static async Task<int> ChallengeStatusAsync(IApiKeyClientResolver resolver) {
		var (_, context, handler) = await AuthenticateAsync(resolver);
		await handler.ChallengeAsync(new AuthenticationProperties());
		return context.Response.StatusCode;
	}

	// ---- Fail-closed ----

	[Fact]
	public async Task No_credential_returns_no_result() {
		var (result, _, _) = await AuthenticateAsync(Resolver(ApiKeyResolveResult.NotFound()), authorization: null);

		result.None.Should().BeTrue();
	}

	[Fact]
	public async Task An_unknown_key_fails_without_throwing() {
		var (result, _, _) = await AuthenticateAsync(Resolver(ApiKeyResolveResult.NotFound()));

		result.Succeeded.Should().BeFalse();
		result.Failure.Should().NotBeNull();
	}

	[Fact]
	public async Task An_ordinary_rejection_challenges_with_401() {
		(await ChallengeStatusAsync(Resolver(ApiKeyResolveResult.NotFound()))).Should().Be(401);
	}

	[Fact]
	public async Task A_missing_routing_signal_challenges_with_400() {
		(await ChallengeStatusAsync(Resolver(ApiKeyResolveResult.MissingRoutingSignal()))).Should().Be(400);
	}

	[Fact]
	public async Task A_revocation_unavailable_outcome_challenges_with_503() {
		(await ChallengeStatusAsync(Resolver(ApiKeyResolveResult.RevocationUnavailable()))).Should().Be(503);
	}

	[Fact]
	public async Task A_configured_key_with_no_expiry_authenticates_under_default_options() {
		// Form-1 configured keys intentionally carry no expiry by default — the consuming app owns the key's
		// lifecycle externally (e.g. Key Vault rotation). The handler chokepoint must NOT reject a no-expiry
		// configured key under default options (RequireExpiry=false, MaxKeyAge=null). Guards N3 against
		// over-reaching into the deliberate "app controls expiry" design.
		const string key = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"; // 40 chars — clears the format floor
		var registry = new ApiKeyClientRegistry();
		registry.Register(new ApiKeyClientEntry(
			"", key, "static-1", "Static One", [], CredentialTransport.BearerAuthorizationHeader));
		var configValidator = new DefaultApiKeyValidator(
			Options.Create(new ApiKeyValidationOptions()), [new Sha256ApiKeyHasher()]);
		var resolver = new ConfigurationApiKeyClientResolver(
			registry, configValidator, NullLogger<ConfigurationApiKeyClientResolver>.Instance);

		var (result, _, _) = await AuthenticateAsync(resolver, authorization: $"Bearer {key}");

		result.Succeeded.Should().BeTrue("a configured key with no expiry authenticates by default — the app owns its lifecycle");
		result.Principal!.FindFirstValue(ClaimTypes.NameIdentifier).Should().Be("static-1");
	}

	// ---- Chokepoint security gates: readiness / revocation / expiry / max-age (N3/N7/N8, subsumes M3) ----

	[Fact]
	public async Task Not_ready_fails_closed_with_503_without_evaluating_the_credential() {
		// The readiness gate lives on the handler now, so it holds for ANY resolver — not just the dispatcher.
		var stub = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client()));
		var notReady = new ApiKeyRevocationReadiness(); // never marked ready

		var (result, context, handler) = await AuthenticateAsync(stub, readiness: notReady);
		await handler.ChallengeAsync(new AuthenticationProperties());

		result.Succeeded.Should().BeFalse();
		context.Response.StatusCode.Should().Be(503, "the denylist is not authoritative yet");
		stub.Calls.Should().Be(0, "no credential is evaluated while revocation state is unknown");
	}

	[Fact]
	public async Task A_revoked_client_is_rejected_at_the_handler_regardless_of_the_resolver() {
		var denylist = new ApiKeyDenylist(
			Options.Create(new ApiKeyRevocationOptions()),
			Options.Create(new ApiKeyValidationOptions()),
			NullLogger<ApiKeyDenylist>.Instance);
		denylist.Revoke("client-1");
		var client = new ApiKeyClient { ClientId = "client-1", ClientName = "Client One" };

		var (result, _, _) = await AuthenticateAsync(
			Resolver(ApiKeyResolveResult.Success(client)), denylist: denylist);

		result.Succeeded.Should().BeFalse("a revoked credential is rejected at the chokepoint, even within a cache TTL");
	}

	[Fact]
	public async Task An_expired_client_is_rejected_even_when_the_resolver_returned_success() {
		// A resolver (or a cache hit) that returns a once-valid, now-expired client must not authenticate —
		// expiry is enforced at the handler, not only inside DynamicApiKeyClientResolver (N7, subsumes M3).
		var client = new ApiKeyClient {
			ClientId = "client-1",
			ClientName = "Client One",
			ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1),
		};

		var (result, _, _) = await AuthenticateAsync(Resolver(ApiKeyResolveResult.Success(client)));

		result.Succeeded.Should().BeFalse("expiry is enforced at the handler chokepoint");
	}

	[Fact]
	public async Task A_client_beyond_its_max_age_is_rejected_at_the_handler() {
		var client = new ApiKeyClient {
			ClientId = "client-1",
			ClientName = "Client One",
			CreatedAt = DateTimeOffset.UtcNow.AddDays(-10),
			MaxKeyAge = TimeSpan.FromDays(1),
		};

		var (result, _, _) = await AuthenticateAsync(Resolver(ApiKeyResolveResult.Success(client)));

		result.Succeeded.Should().BeFalse("a credential beyond its cryptoperiod is rejected at the chokepoint");
	}

	// ---- Success + reserved-claim guard (A7) ----

	[Fact]
	public async Task A_valid_key_authenticates_with_the_expected_first_class_claims() {
		var client = new ApiKeyClient {
			ClientId = "client-1",
			ClientName = "Client One",
			Roles = ["reader"],
			Scopes = ["orders:read"],
		};

		var (result, _, _) = await AuthenticateAsync(Resolver(ApiKeyResolveResult.Success(client)));

		result.Succeeded.Should().BeTrue();
		var principal = result.Principal!;
		principal.FindFirstValue(ClaimTypes.NameIdentifier).Should().Be("client-1");
		principal.FindFirstValue("client_type").Should().Be("api_key");
		principal.FindAll(ClaimTypes.Role).Select(c => c.Value).Should().Contain("reader");
		principal.FindAll("scope").Select(c => c.Value).Should().Contain("orders:read");
	}

	[Fact]
	public async Task Custom_claims_cannot_shadow_reserved_claim_types_A7() {
		var client = new ApiKeyClient {
			ClientId = "client-1",
			ClientName = "Client One",
			Roles = ["real-role"],
			Claims = new Dictionary<string, string> {
				["client_type"] = "spoofed",            // reserved — must be ignored
				[ClaimTypes.Role] = "escalated-role",   // reserved — must be ignored
				[ClaimTypes.NameIdentifier] = "someone-else", // reserved — must be ignored
				["department"] = "engineering",         // ordinary — must pass through
			},
		};

		var (result, _, _) = await AuthenticateAsync(Resolver(ApiKeyResolveResult.Success(client)));

		var principal = result.Principal!;
		principal.FindAll("client_type").Select(c => c.Value).Should().ContainSingle().Which.Should().Be("api_key");
		principal.FindFirstValue(ClaimTypes.NameIdentifier).Should().Be("client-1");
		principal.FindAll(ClaimTypes.Role).Select(c => c.Value).Should().Contain("real-role");
		principal.FindAll(ClaimTypes.Role).Select(c => c.Value).Should().NotContain("escalated-role");
		principal.FindFirstValue("department").Should().Be("engineering", "an ordinary custom claim passes through");
	}

	// ---- Transport filter ----

	[Fact]
	public async Task A_credential_presented_on_an_unaccepted_transport_is_rejected() {
		var client = new ApiKeyClient {
			ClientId = "client-1",
			ClientName = "Client One",
			AcceptedTransports = CredentialTransport.CustomHeader, // not Bearer
		};

		var (result, _, _) = await AuthenticateAsync(Resolver(ApiKeyResolveResult.Success(client)));

		result.Succeeded.Should().BeFalse("the client accepts only the custom-header transport, not Bearer");
	}

	[Fact]
	public async Task A_dynamic_store_key_presented_on_a_custom_header_authenticates_M4() {
		// End-to-end through the real DynamicApiKeyClientResolver -> StoredApiKey.ToApiKeyClient path: a
		// dynamic-store key matched on a custom header must NOT be rejected by the transport gate (M4).
		const string rawKey = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"; // 40 chars — clears the format floor
		const string header = "X-Api-Key";

		var storeValidator = new DefaultApiKeyValidator(
			Options.Create(new ApiKeyValidationOptions()), [new Sha256ApiKeyHasher()]);
		var stored = new StoredApiKey {
			ClientId = "dyn-1",
			ClientName = "Dynamic One",
			HeaderName = header,
			KeyHash = storeValidator.HashKeyEncoded(rawKey),
		};
		var resolver = new TestResolvers.DynamicStore(storeValidator, stored);

		var (result, _, _) = await AuthenticateAsync(
			resolver,
			authorization: null,
			transport: CredentialTransport.CustomHeader,
			customHeaderName: header,
			customHeaderValue: rawKey);

		result.Succeeded.Should().BeTrue("a dynamic-store key matched on a custom header is accepted on that transport");
		result.Principal!.FindFirstValue(ClaimTypes.NameIdentifier).Should().Be("dyn-1");
	}

	[Fact]
	public async Task An_unaccepted_transport_challenges_with_403_N5() {
		var client = new ApiKeyClient {
			ClientId = "client-1",
			ClientName = "Client One",
			AcceptedTransports = CredentialTransport.CustomHeader, // not Bearer
		};

		var (_, context, handler) = await AuthenticateAsync(Resolver(ApiKeyResolveResult.Success(client)));
		await handler.ChallengeAsync(new AuthenticationProperties());

		context.Response.StatusCode.Should().Be(403, "a valid credential on the wrong transport is forbidden, not a re-auth");
	}

	// ---- RFC 6750/7235 challenge tailoring (L3) ----

	[Fact]
	public async Task A_bearer_rejection_advertises_invalid_token_with_a_stable_realm_L3() {
		var (_, context, handler) = await AuthenticateAsync(Resolver(ApiKeyResolveResult.NotFound()));
		await handler.ChallengeAsync(new AuthenticationProperties());

		var wwwAuth = context.Response.Headers.WWWAuthenticate.ToString();
		wwwAuth.Should().Contain("Bearer realm=\"ApiKey\"");
		wwwAuth.Should().Contain("error=\"invalid_token\"", "a credential was presented and rejected");
		wwwAuth.Should().NotContain("ApiKey:Bearer", "the internal scheme name must not leak into the realm");
	}

	[Fact]
	public async Task A_custom_header_scheme_does_not_advertise_bearer_L3() {
		var (_, context, handler) = await AuthenticateAsync(
			Resolver(ApiKeyResolveResult.NotFound()),
			authorization: null,
			transport: CredentialTransport.CustomHeader,
			customHeaderName: "X-Api-Key",
			customHeaderValue: "a-presented-key-value-0123456789ABCD");
		await handler.ChallengeAsync(new AuthenticationProperties());

		context.Response.StatusCode.Should().Be(401);
		context.Response.Headers.WWWAuthenticate.ToString().Should().BeEmpty(
			"a custom-header scheme has no standard auth-scheme to advertise; emitting Bearer would misdirect the client");
	}

	// ---- L2: duplicate credential / routing header ----

	[Fact]
	public async Task A_duplicate_credential_header_challenges_with_400_L2() {
		// Two Authorization headers → non-descript 400, before any resolution (smuggling-disagreement defense).
		var resolver = new TestResolvers.Stub(
			ApiKeyResolveResult.Success(new ApiKeyClient { ClientId = "c", ClientName = "c" }));

		var (result, context, handler) = await AuthenticateAsync(
			resolver, authorizationValues: ["Bearer key-one", "Bearer key-two"]);
		await handler.ChallengeAsync(new AuthenticationProperties());

		result.Succeeded.Should().BeFalse();
		context.Response.StatusCode.Should().Be(400);
		resolver.Calls.Should().Be(0, "the duplicate header is rejected before the resolver runs");
	}

	// ---- N13: claim sanitization ----

	[Fact]
	public async Task Claim_values_with_control_chars_are_dropped_and_roles_scopes_deduped_N13() {
		var client = new ApiKeyClient {
			ClientId = "client-1",
			ClientName = "Client One",
			Roles = ["admin", "admin", "reader"],          // duplicate
			Scopes = ["orders:read", "orders:read"],        // duplicate
			Claims = new Dictionary<string, string> {
				["safe"] = "engineering",
				["danger"] = "value\r\nInjected-Header: x", // control characters
			},
		};

		var (result, _, _) = await AuthenticateAsync(Resolver(ApiKeyResolveResult.Success(client)));

		var p = result.Principal!;
		p.FindAll(ClaimTypes.Role).Select(c => c.Value).Should().BeEquivalentTo(["admin", "reader"]);
		p.FindAll("scope").Should().ContainSingle();
		p.FindFirstValue("safe").Should().Be("engineering");
		p.FindFirst("danger").Should().BeNull("a control-character claim value is dropped");
	}
}
