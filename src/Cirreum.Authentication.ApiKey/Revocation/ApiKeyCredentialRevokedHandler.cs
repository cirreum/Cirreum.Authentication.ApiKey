namespace Cirreum.Authentication.ApiKey;

using Cirreum.Authentication.Events;

/// <summary>
/// Handles <see cref="CredentialRevoked"/> auth-bus events by adding the revoked credential to the
/// <see cref="IApiKeyDenylist"/> (ADR-0020 §8). Idempotent — the same event may be delivered more
/// than once in a distributed deployment. Events are accepted when untyped or typed
/// <c>"apikey"</c>; ids for other credential types never match an ApiKey <c>ClientId</c>, so storing
/// them is harmless.
/// </summary>
internal sealed class ApiKeyCredentialRevokedHandler(
	IApiKeyDenylist denylist
) : IAuthenticationEventHandler<CredentialRevoked> {

	/// <summary>The <see cref="CredentialRevoked.CredentialType"/> value this scheme publishes/handles.</summary>
	public const string ApiKeyCredentialType = "apikey";

	/// <inheritdoc />
	public ValueTask HandleAsync(CredentialRevoked evt, CancellationToken cancellationToken = default) {
		if (evt is null) {
			return ValueTask.CompletedTask;
		}

		if (evt.CredentialType is null
			|| string.Equals(evt.CredentialType, ApiKeyCredentialType, StringComparison.OrdinalIgnoreCase)) {
			// Thread the revoked credential's own expiry through so the denylist can safely evict the
			// entry once the credential can no longer authenticate anyway (it never evicts to free space).
			// null (unknown expiry) means retain until restart — see IApiKeyDenylist.Revoke.
			denylist.Revoke(evt.CredentialId, evt.ExpiresAt);
		}

		return ValueTask.CompletedTask;
	}

}