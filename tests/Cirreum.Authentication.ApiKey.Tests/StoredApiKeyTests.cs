namespace Cirreum.Authentication.ApiKey.Tests;

using Cirreum.AuthenticationProvider;

/// <summary>
/// Proofs for <see cref="StoredApiKey.ToApiKeyClient"/>: the built client is accepted on the transport it
/// was presented (and matched) on — so a dynamic-store key on a custom header is not rejected by the
/// handler's transport gate (M4) — and the cryptoperiod fields flow through for chokepoint enforcement.
/// </summary>
public sealed class StoredApiKeyTests {

	private static StoredApiKey Stored() => new() {
		ClientId = "dyn-1",
		ClientName = "Dynamic One",
		HeaderName = "X-Api-Key",
		KeyHash = "sha256$irrelevant",
	};

	[Theory]
	[InlineData(CredentialTransport.CustomHeader)]
	[InlineData(CredentialTransport.BearerAuthorizationHeader)]
	public void ToApiKeyClient_accepts_the_presented_transport(CredentialTransport transport) {
		var client = Stored().ToApiKeyClient(transport);

		client.AcceptedTransports.Should().Be(transport,
			"the credential matched on this transport, so it is accepted on it (no hardcoded Bearer default)");
	}

	[Fact]
	public void ToApiKeyClient_flows_the_cryptoperiod_fields_for_chokepoint_enforcement() {
		var created = DateTimeOffset.UtcNow.AddDays(-1);
		var expires = DateTimeOffset.UtcNow.AddDays(1);
		var stored = Stored() with { CreatedAt = created, ExpiresAt = expires, MaxKeyAge = TimeSpan.FromDays(30) };

		var client = stored.ToApiKeyClient(CredentialTransport.CustomHeader);

		client.CreatedAt.Should().Be(created);
		client.ExpiresAt.Should().Be(expires);
		client.MaxKeyAge.Should().Be(TimeSpan.FromDays(30));
	}
}
