namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Manages the collection of registered ApiKey clients and provides constant-time
/// validation of presented keys. Single shared instance across all configured ApiKey
/// scheme instances — the registry is the source of truth for the
/// <see cref="ApiKeyAuthenticationHandler"/>.
/// </summary>
public sealed class ApiKeyClientRegistry {

	private readonly List<ApiKeyClientEntry> _clients = [];

	/// <summary>
	/// Registers an ApiKey client entry. <b>Composition-time only</b> — called by the registrar while the
	/// host is being built; the backing list is read lock-free on the request hot path, so it must not be
	/// mutated after composition. Internal (not public) to enforce this, mirroring
	/// <see cref="ApiKeySourceCatalog"/>.
	/// </summary>
	internal void Register(ApiKeyClientEntry client) {
		this._clients.Add(client);
	}

	/// <summary>
	/// Validates a key presented on a custom header. Returns the matching entry
	/// when found, otherwise <see langword="null"/>. Uses constant-time comparison.
	/// </summary>
	public ApiKeyClientEntry? ValidateCustomHeaderKey(string headerName, string providedKey) {
		if (IsBlank(providedKey)) {
			return null;
		}

		var providedBytes = Encoding.UTF8.GetBytes(providedKey);

		foreach (var client in this._clients) {
			if (!client.AcceptedTransports.HasFlag(CredentialTransport.CustomHeader)) {
				continue;
			}
			// Header names are case-insensitive per RFC 9110; the key below is not.
			if (!string.Equals(client.HeaderName, headerName, StringComparison.OrdinalIgnoreCase)) {
				continue;
			}
			if (IsBlank(client.Key)) {
				continue;
			}
			var expectedBytes = Encoding.UTF8.GetBytes(client.Key);
			if (CryptographicOperations.FixedTimeEquals(providedBytes, expectedBytes)) {
				return client;
			}
		}

		return null;
	}

	/// <summary>
	/// Validates a key presented via <c>Authorization: Bearer</c>. Returns the
	/// matching entry when found, otherwise <see langword="null"/>. Uses constant-
	/// time comparison.
	/// </summary>
	public ApiKeyClientEntry? ValidateBearerKey(string providedKey) {
		if (IsBlank(providedKey)) {
			return null;
		}

		var providedBytes = Encoding.UTF8.GetBytes(providedKey);

		foreach (var client in this._clients) {
			if (!client.AcceptedTransports.HasFlag(CredentialTransport.BearerAuthorizationHeader)) {
				continue;
			}
			if (IsBlank(client.Key)) {
				continue;
			}
			var expectedBytes = Encoding.UTF8.GetBytes(client.Key);
			if (CryptographicOperations.FixedTimeEquals(providedBytes, expectedBytes)) {
				return client;
			}
		}

		return null;
	}

	// FixedTimeEquals reports two zero-length spans as equal, so a blank presented key would match a
	// blank configured one. Neither reaches here today — ValidateFormat imposes a length floor on
	// what is presented, and the registrar an entropy floor on what is configured — but a credential
	// comparison that is only safe because of invariants held in two other files is one refactor
	// away from being wrong. DefaultApiKeyValidator.CompareKeysSecurely guards this the same way.
	private static bool IsBlank(string? key) => string.IsNullOrWhiteSpace(key);

}
