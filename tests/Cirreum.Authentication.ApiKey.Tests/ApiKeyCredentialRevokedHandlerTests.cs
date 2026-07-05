namespace Cirreum.Authentication.ApiKey.Tests;

using Cirreum.Authentication.Events;

/// <summary>
/// Proofs for <see cref="ApiKeyCredentialRevokedHandler"/>: it adds the revoked credential to the
/// denylist, threads the credential's own expiry through, filters by credential type, and is
/// null-safe.
/// </summary>
public sealed class ApiKeyCredentialRevokedHandlerTests {

	private static readonly DateTimeOffset OccurredAt = new(2026, 7, 5, 12, 0, 0, TimeSpan.Zero);

	private static (ApiKeyCredentialRevokedHandler handler, IApiKeyDenylist denylist) Build() {
		var denylist = Substitute.For<IApiKeyDenylist>();
		return (new ApiKeyCredentialRevokedHandler(denylist), denylist);
	}

	[Fact]
	public async Task An_apikey_typed_event_revokes_the_credential_with_its_expiry() {
		var (handler, denylist) = Build();
		var expiresAt = OccurredAt.AddDays(30);

		await handler.HandleAsync(new CredentialRevoked("client-1", "subject-1", OccurredAt) {
			CredentialType = "apikey",
			ExpiresAt = expiresAt,
		});

		denylist.Received(1).Revoke("client-1", expiresAt);
	}

	[Fact]
	public async Task An_untyped_event_is_accepted_and_threads_a_null_expiry() {
		var (handler, denylist) = Build();

		await handler.HandleAsync(new CredentialRevoked("client-1", "subject-1", OccurredAt));

		// CredentialType null (untyped) is accepted; ExpiresAt null flows through as "retain until restart".
		denylist.Received(1).Revoke("client-1", null);
	}

	[Fact]
	public async Task The_credential_type_match_is_case_insensitive() {
		var (handler, denylist) = Build();

		await handler.HandleAsync(new CredentialRevoked("client-1", "subject-1", OccurredAt) { CredentialType = "ApiKey" });

		denylist.Received(1).Revoke("client-1", Arg.Any<DateTimeOffset?>());
	}

	[Fact]
	public async Task An_event_for_a_different_credential_type_is_ignored() {
		var (handler, denylist) = Build();

		await handler.HandleAsync(new CredentialRevoked("token-1", "subject-1", OccurredAt) { CredentialType = "signedrequest" });

		denylist.DidNotReceive().Revoke(Arg.Any<string>(), Arg.Any<DateTimeOffset?>());
	}

	[Fact]
	public async Task A_null_event_is_a_no_op() {
		var (handler, denylist) = Build();

		await handler.HandleAsync(null!);

		denylist.DidNotReceive().Revoke(Arg.Any<string>(), Arg.Any<DateTimeOffset?>());
	}

}
