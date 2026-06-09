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
			CredentialTransport transport = CredentialTransport.BearerAuthorizationHeader) {

		var options = new ApiKeyAuthenticationOptions { Transport = transport };
		var monitor = Substitute.For<IOptionsMonitor<ApiKeyAuthenticationOptions>>();
		monitor.Get(Arg.Any<string>()).Returns(options);

		var handler = new ApiKeyAuthenticationHandler(
			monitor, NullLoggerFactory.Instance, UrlEncoder.Default, resolver);

		var context = new DefaultHttpContext { RequestServices = new ServiceCollection().BuildServiceProvider() };
		context.Request.Method = "GET";
		if (authorization is not null) {
			context.Request.Headers.Authorization = authorization;
		}

		var scheme = new AuthenticationScheme(Scheme, Scheme, typeof(ApiKeyAuthenticationHandler));
		await handler.InitializeAsync(scheme, context);
		return (await handler.AuthenticateAsync(), context, handler);
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
}
