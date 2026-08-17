namespace Cirreum.Authentication.ApiKey.Tests;

using Cirreum.AuthenticationProvider;
using Cirreum.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Proofs that custom-header scheme registration validates the header name as an RFC 7230 token (N6), so a
/// non-token name fails fast at startup rather than flowing into a malformed scheme name / WWW-Authenticate.
/// </summary>
public sealed class ApiKeySchemeRegistrationTests {

	private static IAuthenticationBuilder NewBuilder() {
		var services = new ServiceCollection();
		return new TestAuthenticationBuilder(
			services,
			new AuthenticationBuilder(services),
			new ConfigurationBuilder().Build());
	}

	[Theory]
	[InlineData("X Api Key")]   // space is not a tchar
	[InlineData("X-Api-Key\"")] // double-quote is not a tchar
	[InlineData("X\tApi")]      // tab is not a tchar
	[InlineData("X-Api-Key\r")] // CR is not a tchar
	public void TryRegisterCustomHeader_rejects_a_non_token_header_name_N6(string headerName) {
		var builder = NewBuilder();

		var act = () => ApiKeySchemeRegistration.TryRegisterCustomHeader(builder, SubjectKind.Machine, headerName);

		act.Should().Throw<ArgumentException>();
	}

	[Theory]
	[InlineData("X-Api-Key")]
	[InlineData("Ocp-Apim-Subscription-Key")]
	[InlineData("X-Partner.ApiKey_1")]
	public void TryRegisterCustomHeader_accepts_a_token_header_name(string headerName) {
		var builder = NewBuilder();

		var act = () => ApiKeySchemeRegistration.TryRegisterCustomHeader(builder, SubjectKind.Machine, headerName);

		act.Should().NotThrow();
	}

	private sealed class TestAuthenticationBuilder(
		IServiceCollection services,
		AuthenticationBuilder authBuilder,
		IConfiguration configuration) : IAuthenticationBuilder {

		public IServiceCollection Services { get; } = services;
		public AuthenticationBuilder AuthBuilder { get; } = authBuilder;
		public IConfiguration Configuration { get; } = configuration;

		public IAuthenticationBuilder DeclareScheme(string scheme, SubjectKind subjectKind,
			ClaimAuthority profile = ClaimAuthority.Unspecified,
			ClaimAuthority roles = ClaimAuthority.Unspecified) {
			this.Services.AddSingleton(new SchemeClaimAuthorityRegistration(scheme, subjectKind, profile, roles));
			return this;
		}

		public IAuthenticationBuilder AddScheme<TOptions, THandler>(string scheme, SubjectKind subjectKind,
			ClaimAuthority profile = ClaimAuthority.Unspecified,
			ClaimAuthority roles = ClaimAuthority.Unspecified,
			Action<TOptions>? configureOptions = null)
			where TOptions : AuthenticationSchemeOptions, new()
			where THandler : AuthenticationHandler<TOptions> {
			this.DeclareScheme(scheme, subjectKind, profile, roles);
			this.AuthBuilder.AddScheme<TOptions, THandler>(scheme, configureOptions);
			return this;
		}
	}
}
