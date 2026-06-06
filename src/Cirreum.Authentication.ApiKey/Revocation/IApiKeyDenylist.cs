namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// An in-memory denylist of revoked API key credential identifiers (ADR-0020 §8). It is the
/// correctness mechanism for revocation: the resolver consults it on every resolution, so a revoked
/// credential is rejected even if a cache entry for it has not yet expired. It is hydrated at boot
/// from <c>IRevokedCredentialProvider</c> and kept current by <c>CredentialRevoked</c> auth events.
/// </summary>
public interface IApiKeyDenylist {

	/// <summary>Returns whether the given credential identifier (an ApiKey <c>ClientId</c>) is revoked.</summary>
	bool IsRevoked(string credentialId);

	/// <summary>Adds a credential identifier to the denylist. Idempotent.</summary>
	void Revoke(string credentialId);

}
