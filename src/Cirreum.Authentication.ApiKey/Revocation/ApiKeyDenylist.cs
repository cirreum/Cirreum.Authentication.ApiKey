namespace Cirreum.Authentication.ApiKey;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;

/// <summary>
/// Default <see cref="IApiKeyDenylist"/> — a thread-safe in-memory map (credential id → the revoked
/// credential's own optional expiry) with lock-free reads, suitable for the per-request hot path.
/// Registered as a singleton.
/// </summary>
/// <remarks>
/// <para>
/// Growth is bounded by <see cref="ApiKeyRevocationOptions.MaxDenylistEntries"/>. Two safety rules hold
/// absolutely: a live revoked entry is <em>never</em> evicted to make room (that would un-revoke a
/// still-usable credential), and a revocation is <em>never</em> silently dropped. When the cap is hit,
/// entries whose credential has already expired are reclaimed first; if still full, the revocation is
/// refused, logged <c>Critical</c>, and the denylist latches <see cref="IsAuthoritative"/> = <c>false</c>
/// so the handler fails all ApiKey auth closed (503) rather than risk honoring the revocation it could not
/// record (N18). The scale-out path past the cap is a pluggable <see cref="IApiKeyDenylist"/> backed by the
/// authoritative store (e.g. a counting-Bloom filter).
/// </para>
/// <para>
/// The cap is enforced best-effort under concurrency: simultaneous revocations near the limit may
/// transiently overshoot it by up to the concurrency level (a check-then-act on a lock-free dictionary).
/// The two safety rules above are unaffected — the overshoot only over-counts; nothing is lost (N11).
/// </para>
/// </remarks>
public sealed class ApiKeyDenylist : IApiKeyDenylist {

	private readonly ConcurrentDictionary<string, DateTimeOffset?> _revoked = new(StringComparer.Ordinal);
	private readonly int _maxEntries;
	private readonly bool _allowExpiredKeys;
	private readonly TimeSpan _evictionGrace;
	private readonly ILogger<ApiKeyDenylist> _logger;
	private int _overflowLogged;
	private volatile bool _authoritative = true;

	/// <summary>Initializes a new instance bound to the configured revocation and validation options.</summary>
	/// <remarks>
	/// The validation options matter for eviction safety: evict-on-expiry must never reclaim a revoked
	/// entry while the validator would <em>still accept</em> the underlying credential. So eviction is
	/// disabled entirely when <see cref="ApiKeyValidationOptions.AllowExpiredKeys"/> is set (the validator
	/// honors the key forever), and otherwise deferred to <c>expiry + ExpirationGracePeriod</c> — the
	/// validator's true rejection point — rather than the raw expiry (N15).
	/// </remarks>
	public ApiKeyDenylist(
		IOptions<ApiKeyRevocationOptions> options,
		IOptions<ApiKeyValidationOptions> validationOptions,
		ILogger<ApiKeyDenylist> logger) {
		var max = options?.Value?.MaxDenylistEntries ?? 0;
		this._maxEntries = max > 0 ? max : 1_000_000;
		this._allowExpiredKeys = validationOptions?.Value?.AllowExpiredKeys ?? false;
		this._evictionGrace = validationOptions?.Value?.ExpirationGracePeriod ?? TimeSpan.Zero;
		this._logger = logger ?? throw new ArgumentNullException(nameof(logger));
	}

	/// <inheritdoc />
	public bool IsAuthoritative => this._authoritative;

	/// <inheritdoc />
	public bool IsRevoked(string credentialId) {
		if (string.IsNullOrEmpty(credentialId) || !this._revoked.TryGetValue(credentialId, out var expiresAt)) {
			return false;
		}

		if (this.IsExpiryReclaimable(expiresAt)) {
			// The revoked credential has expired AND the validator would also reject it, so the entry is
			// dead weight — reclaim it. This never un-revokes a credential the validator still honors. The
			// KeyValuePair overload removes only if the expiry still matches, so a concurrent re-revoke with
			// a new expiry is preserved.
			this._revoked.TryRemove(new KeyValuePair<string, DateTimeOffset?>(credentialId, expiresAt));
			return false;
		}

		return true;
	}

	/// <summary>
	/// Whether a denylist entry's credential expiry has passed the point where the validator would also
	/// reject the credential — the only point at which evicting the revocation entry is safe (N15). False
	/// when <see cref="ApiKeyValidationOptions.AllowExpiredKeys"/> is set (the validator never rejects on
	/// expiry, so the revocation must persist) or when still within <c>expiry + ExpirationGracePeriod</c>.
	/// </summary>
	private bool IsExpiryReclaimable(DateTimeOffset? expiresAt) =>
		!this._allowExpiredKeys
		&& expiresAt is { } exp
		&& DateTimeOffset.UtcNow >= exp + this._evictionGrace;

	/// <summary>
	/// Returns the <em>wider</em> retention of two expiries (a refine must never shorten retention).
	/// <see langword="null"/> means "retain until restart" — the widest — so it always wins; otherwise the
	/// later instant wins.
	/// </summary>
	private static DateTimeOffset? Widen(DateTimeOffset? existing, DateTimeOffset? incoming) {
		if (existing is null || incoming is null) {
			return null;
		}
		return incoming > existing ? incoming : existing;
	}

	/// <inheritdoc />
	public void Revoke(string credentialId, DateTimeOffset? expiresAt = null) {
		if (string.IsNullOrEmpty(credentialId)) {
			return;
		}

		// Refining an existing entry (e.g. attaching/updating its expiry) is always allowed and does not
		// count against the cap. Widen-only: never shorten a live revocation's retention — a refine to an
		// earlier (or past) expiry could make the entry reclaimable and silently un-revoke a credential the
		// validator still honors. null = retain until restart (the widest), so it always wins.
		if (this._revoked.TryGetValue(credentialId, out var existing)) {
			this._revoked[credentialId] = Widen(existing, expiresAt);
			return;
		}

		if (this._revoked.Count >= this._maxEntries) {
			// Reclaim space only from entries whose credential has already expired (safe — those
			// credentials are dead regardless of the denylist).
			this.SweepExpired();
		}

		if (this._revoked.Count >= this._maxEntries) {
			// At cap with nothing safe to reclaim. Refuse — never evict a live revoked entry to make room,
			// never silently drop. The denylist is now non-authoritative (it is missing this revocation), so
			// it latches IsAuthoritative=false: the handler then fails ALL ApiKey auth closed (503) rather
			// than risk honoring a revoked credential (N18). Recovery is a restart + re-hydration from the
			// authoritative store (a larger cap, or a scale-out denylist). Log Critical once.
			this._authoritative = false;
			if (Interlocked.Exchange(ref this._overflowLogged, 1) == 0) {
				if (this._logger.IsEnabled(LogLevel.Critical)) {
					this._logger.LogCritical(
						"ApiKey denylist reached its cap of {Max} entries; refusing to record further revocations and " +
						"failing ApiKey authentication closed (503). Raise " +
						"Cirreum:Authentication:Providers:ApiKey:Revocation:MaxDenylistEntries, or move to a scale-out " +
						"denylist backed by the authoritative store, then restart.", this._maxEntries);
				}
			}

			return;
		}

		this._revoked[credentialId] = expiresAt;
	}

	private void SweepExpired() {
		var reclaimed = false;

		foreach (var kvp in this._revoked) {
			// Only reclaim entries whose credential the validator would also reject (N15) — never a live
			// revoked entry, and never one still honored under AllowExpiredKeys / within the grace window.
			if (this.IsExpiryReclaimable(kvp.Value)) {
				if (this._revoked.TryRemove(kvp)) {
					reclaimed = true;
				}
			}
		}

		// Re-arm the overflow latch if a sweep freed space, so a later overflow re-alerts.
		if (reclaimed) {
			Interlocked.Exchange(ref this._overflowLogged, 0);
		}
	}

}
