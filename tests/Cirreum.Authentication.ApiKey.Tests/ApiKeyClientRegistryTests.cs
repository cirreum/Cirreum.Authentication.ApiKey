namespace Cirreum.Authentication.ApiKey.Tests;

using Cirreum.AuthenticationProvider;

/// <summary>
/// Blank-credential proofs for <see cref="ApiKeyClientRegistry"/>.
/// </summary>
/// <remarks>
/// <see cref="System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(System.ReadOnlySpan{byte}, System.ReadOnlySpan{byte})"/>
/// reports two zero-length spans as equal, so a comparison that reaches it with blanks on both sides
/// authenticates rather than rejects. Upstream checks make that unreachable in the composed pipeline;
/// these lock the registry's own behaviour so it does not depend on them.
/// </remarks>
public sealed class ApiKeyClientRegistryTests {

	private const string Header = "X-Api-Key";

	private static ApiKeyClientRegistry RegistryWith(string key, CredentialTransport transports) {
		var registry = new ApiKeyClientRegistry();
		registry.Register(new ApiKeyClientEntry(
			HeaderName: Header,
			Key: key,
			ClientId: "client-1",
			ClientName: "Client One",
			Roles: [],
			AcceptedTransports: transports));
		return registry;
	}

	[Theory]
	[InlineData("")]
	[InlineData("   ")]
	public void A_blank_key_never_matches_a_blank_configured_key_on_a_custom_header(string blank) {
		var registry = RegistryWith(blank, CredentialTransport.CustomHeader);

		registry.ValidateCustomHeaderKey(Header, blank).Should().BeNull();
	}

	[Theory]
	[InlineData("")]
	[InlineData("   ")]
	public void A_blank_key_never_matches_a_blank_configured_key_on_bearer(string blank) {
		var registry = RegistryWith(blank, CredentialTransport.BearerAuthorizationHeader);

		registry.ValidateBearerKey(blank).Should().BeNull();
	}

	[Fact]
	public void A_blank_presented_key_never_matches_a_real_configured_key() {
		var registry = RegistryWith("a-real-and-sufficiently-long-key", CredentialTransport.BearerAuthorizationHeader);

		registry.ValidateBearerKey(string.Empty).Should().BeNull();
	}

	[Fact]
	public void A_real_presented_key_never_matches_a_blank_configured_key() {
		var registry = RegistryWith(string.Empty, CredentialTransport.BearerAuthorizationHeader);

		registry.ValidateBearerKey("a-real-and-sufficiently-long-key").Should().BeNull();
	}

	[Fact]
	public void A_matching_key_still_resolves_its_client() {
		const string Key = "a-real-and-sufficiently-long-key";
		var registry = RegistryWith(Key, CredentialTransport.BearerAuthorizationHeader);

		registry.ValidateBearerKey(Key)!.ClientId.Should().Be("client-1");
	}

	[Fact]
	public void A_key_differing_only_in_case_does_not_match() {
		const string Key = "MixedCaseApiKeyValueForTesting";
		var registry = RegistryWith(Key, CredentialTransport.BearerAuthorizationHeader);

		registry.ValidateBearerKey(Key.ToLowerInvariant()).Should().BeNull();
	}
}
