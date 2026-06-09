namespace Cirreum.Authentication.ApiKey;

using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

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
/// refused and logged <c>Critical</c>. The scale-out path past the cap is a pluggable
/// <see cref="IApiKeyDenylist"/> backed by the authoritative store (e.g. a counting-Bloom filter).
/// </para>
/// </remarks>
public sealed class ApiKeyDenylist : IApiKeyDenylist {

	private readonly ConcurrentDictionary<string, DateTimeOffset?> _revoked = new(StringComparer.Ordinal);
	private readonly int _maxEntries;
	private readonly ILogger<ApiKeyDenylist> _logger;
	private int _overflowLogged;

	/// <summary>Initializes a new instance bound to the configured revocation options.</summary>
	public ApiKeyDenylist(IOptions<ApiKeyRevocationOptions> options, ILogger<ApiKeyDenylist> logger) {
		var max = options?.Value?.MaxDenylistEntries ?? 0;
		this._maxEntries = max > 0 ? max : 1_000_000;
		this._logger = logger ?? throw new ArgumentNullException(nameof(logger));
	}

	/// <inheritdoc />
	public bool IsRevoked(string credentialId) {
		if (string.IsNullOrEmpty(credentialId) || !this._revoked.TryGetValue(credentialId, out var expiresAt)) {
			return false;
		}

		if (expiresAt is { } exp && DateTimeOffset.UtcNow >= exp) {
			// The revoked credential has itself expired — it can no longer authenticate (the validator
			// rejects expired keys), so the entry is dead weight. Evict it. This does NOT un-revoke a
			// live credential. The KeyValuePair overload removes only if the expiry still matches, so a
			// concurrent re-revoke with a new expiry is preserved.
			this._revoked.TryRemove(new KeyValuePair<string, DateTimeOffset?>(credentialId, expiresAt));
			return false;
		}

		return true;
	}

	/// <inheritdoc />
	public void Revoke(string credentialId, DateTimeOffset? expiresAt = null) {
		if (string.IsNullOrEmpty(credentialId)) {
			return;
		}

		// Refining an existing entry (e.g. attaching/updating its expiry) is always allowed and does not
		// count against the cap.
		if (this._revoked.ContainsKey(credentialId)) {
			this._revoked[credentialId] = expiresAt;
			return;
		}

		if (this._revoked.Count >= this._maxEntries) {
			// Reclaim space only from entries whose credential has already expired (safe — those
			// credentials are dead regardless of the denylist).
			this.SweepExpired();
		}

		if (this._revoked.Count >= this._maxEntries) {
			// At cap with nothing safe to reclaim. Refuse — never evict a live revoked entry to make
			// room, never silently drop. Log Critical once so the standing condition is alerted on.
			if (Interlocked.Exchange(ref this._overflowLogged, 1) == 0) {
				this._logger.LogCritical(
					"ApiKey denylist reached its cap of {Max} entries; refusing to record further revocations. " +
					"A newly revoked credential may continue to authenticate. Raise " +
					"Cirreum:Authentication:Providers:ApiKey:Revocation:MaxDenylistEntries, or move to a scale-out " +
					"denylist backed by the authoritative store.", this._maxEntries);
			}

			return;
		}

		this._revoked[credentialId] = expiresAt;
	}

	private void SweepExpired() {
		var now = DateTimeOffset.UtcNow;
		var reclaimed = false;

		foreach (var kvp in this._revoked) {
			if (kvp.Value is { } exp && now >= exp) {
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
