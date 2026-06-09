namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Options for the ApiKey revocation denylist (ADR-0020 §8). Bound from
/// <c>Cirreum:Authentication:Providers:ApiKey:Revocation</c>.
/// </summary>
public sealed class ApiKeyRevocationOptions {

	/// <summary>
	/// When <see langword="false"/> (the default), a boot-time denylist hydration that <em>faults</em>
	/// — a registered <c>IRevokedCredentialProvider</c> throws, so the denylist may be missing revoked
	/// credentials — leaves API-key authentication failing closed (a non-descript <c>503</c>) and the
	/// health check <c>Unhealthy</c> until hydration succeeds. Set to <see langword="true"/> ONLY to
	/// deliberately serve with a possibly-incomplete denylist (availability over the revocation
	/// guarantee): a revoked credential could authenticate until the live event stream catches up. The
	/// name is intentionally blunt — turning this on accepts that a revoked key may be honored.
	/// </summary>
	public bool AllowFaultedDenylist { get; set; }

	/// <summary>
	/// The maximum number of entries the in-memory denylist will hold (ADR-0020 §8 — bounded growth).
	/// Reaching the cap is logged <c>Critical</c> and further revocations are <em>refused</em> (never
	/// silently dropped, and never evicted to make room — evicting a revoked entry would un-revoke a
	/// credential). Size this above the realistic revoked-credential population; the authoritative store
	/// remains the source of truth, and a scale-out denylist (e.g. a counting-Bloom filter) is the path
	/// past this cap. Default 1,000,000.
	/// </summary>
	public int MaxDenylistEntries { get; set; } = 1_000_000;
}
