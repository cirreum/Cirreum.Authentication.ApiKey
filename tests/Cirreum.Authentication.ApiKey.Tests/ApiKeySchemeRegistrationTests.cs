namespace Cirreum.Authentication.ApiKey.Tests;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Proofs that custom-header scheme registration validates the header name as an RFC 7230 token (N6), so a
/// non-token name fails fast at startup rather than flowing into a malformed scheme name / WWW-Authenticate.
/// </summary>
public sealed class ApiKeySchemeRegistrationTests {

	[Theory]
	[InlineData("X Api Key")]   // space is not a tchar
	[InlineData("X-Api-Key\"")] // double-quote is not a tchar
	[InlineData("X\tApi")]      // tab is not a tchar
	[InlineData("X-Api-Key\r")] // CR is not a tchar
	public void TryRegisterCustomHeader_rejects_a_non_token_header_name_N6(string headerName) {
		var services = new ServiceCollection();
		var authBuilder = new AuthenticationBuilder(services);

		var act = () => ApiKeySchemeRegistration.TryRegisterCustomHeader(services, authBuilder, headerName);

		act.Should().Throw<ArgumentException>();
	}

	[Theory]
	[InlineData("X-Api-Key")]
	[InlineData("Ocp-Apim-Subscription-Key")]
	[InlineData("X-Partner.ApiKey_1")]
	public void TryRegisterCustomHeader_accepts_a_token_header_name(string headerName) {
		var services = new ServiceCollection();
		var authBuilder = new AuthenticationBuilder(services);

		var act = () => ApiKeySchemeRegistration.TryRegisterCustomHeader(services, authBuilder, headerName);

		act.Should().NotThrow();
	}
}
