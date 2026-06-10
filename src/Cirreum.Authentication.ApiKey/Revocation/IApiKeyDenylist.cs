namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// An in-memory denylist of revoked API key credential identifiers (ADR-0020 §8). It is the
/// correctness mechanism for revocation: the handler consults it on every resolution, so a revoked
/// credential is rejected even if a cache entry for it has not yet expired. It is hydrated at boot
/// from <c>IRevokedCredentialProvider</c> and kept current by <c>CredentialRevoked</c> auth events.
/// </summary>
/// <remarks>
/// <para>
/// <b>Identifier contract (case-sensitivity):</b> credential identifiers are matched with
/// <see cref="System.StringComparer.Ordinal"/> — byte-for-byte, case-sensitive. The identifiers supplied
/// to <see cref="Revoke"/> (from <c>CredentialRevoked.CredentialId</c> and
/// <c>IRevokedCredentialProvider</c>, typically an external admin/issuance system) MUST be the exact same
/// string — same casing — as the <c>ApiKeyClient.ClientId</c> the resolver returns for that credential.
/// A mismatch in case (e.g. <c>"Client-A"</c> revoked but <c>"client-a"</c> resolved) is a silent
/// revocation miss: the revoked credential keeps authenticating. Normalize identifiers at issuance so the
/// producer and the store agree.
/// </para>
/// </remarks>
public interface IApiKeyDenylist {

	/// <summary>Returns whether the given credential identifier (an ApiKey <c>ClientId</c>) is revoked.</summary>
	bool IsRevoked(string credentialId);

	/// <summary>
	/// Whether the denylist is still authoritative — i.e. it is recording every revocation it is told about.
	/// Returns <see langword="false"/> once it has had to <em>refuse</em> a revocation (e.g. a bounded
	/// in-memory denylist that reached its cap with nothing safe to reclaim): from that point it may be
	/// missing a revoked credential, so consumers must fail closed rather than risk honoring one (N18). The
	/// default is <see langword="true"/> for implementations that cannot lose a revocation (e.g. one backed
	/// by the authoritative store).
	/// </summary>
	bool IsAuthoritative => true;

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
