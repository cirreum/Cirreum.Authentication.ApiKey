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

	/// <summary>
	/// Adds a credential identifier to the denylist. Idempotent. The optional <paramref name="expiresAt"/>
	/// is the revoked <em>credential's own</em> expiry: once past, the credential can no longer
	/// authenticate, so the denylist entry is safely evicted (it never evicts to free space, since that
	/// would un-revoke a still-live credential). When <see langword="null"/>, the entry is retained
	/// until process restart. Implementations bound total growth and refuse — never silently drop —
	/// once a cap is reached.
	/// </summary>
	/// <param name="credentialId">The credential identifier to revoke.</param>
	/// <param name="expiresAt">The revoked credential's own expiry, if known; otherwise <see langword="null"/>.</param>
	void Revoke(string credentialId, DateTimeOffset? expiresAt = null);

}
