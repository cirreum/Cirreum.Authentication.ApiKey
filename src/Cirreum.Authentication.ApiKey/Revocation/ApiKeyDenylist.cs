namespace Cirreum.Authentication.ApiKey;

using System.Collections.Concurrent;

/// <summary>
/// Default <see cref="IApiKeyDenylist"/> — a thread-safe in-memory set with lock-free reads, suitable
/// for the per-request hot path. Registered as a singleton.
/// </summary>
public sealed class ApiKeyDenylist : IApiKeyDenylist {

	private readonly ConcurrentDictionary<string, byte> _revoked = new(StringComparer.Ordinal);

	/// <inheritdoc />
	public bool IsRevoked(string credentialId) =>
		!string.IsNullOrEmpty(credentialId) && this._revoked.ContainsKey(credentialId);

	/// <inheritdoc />
	public void Revoke(string credentialId) {
		if (!string.IsNullOrEmpty(credentialId)) {
			this._revoked[credentialId] = 0;
		}
	}

}
