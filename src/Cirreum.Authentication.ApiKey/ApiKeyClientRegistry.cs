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
	/// Registers an ApiKey client entry.
	/// </summary>
	public void Register(ApiKeyClientEntry client) {
		_clients.Add(client);
	}

	/// <summary>
	/// Validates a key presented on a custom header. Returns the matching entry
	/// when found, otherwise <see langword="null"/>. Uses constant-time comparison.
	/// </summary>
	public ApiKeyClientEntry? ValidateCustomHeaderKey(string headerName, string providedKey) {
		var providedBytes = Encoding.UTF8.GetBytes(providedKey);

		foreach (var client in _clients) {
			if (!client.AcceptedTransports.HasFlag(CredentialTransport.CustomHeader)) {
				continue;
			}
			if (!string.Equals(client.HeaderName, headerName, StringComparison.OrdinalIgnoreCase)) {
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
		var providedBytes = Encoding.UTF8.GetBytes(providedKey);

		foreach (var client in _clients) {
			if (!client.AcceptedTransports.HasFlag(CredentialTransport.BearerAuthorizationHeader)) {
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
	/// Gets all distinct custom-header names that have registered clients accepting
	/// the <see cref="CredentialTransport.CustomHeader"/> transport. Consumed by
	/// <see cref="ConfigurationApiKeyClientResolver.SupportedHeaders"/> at runtime so
	/// resolvers know which custom headers to handle.
	/// </summary>
	public IReadOnlySet<string> RegisteredCustomHeaders =>
		_clients
			.Where(c => c.AcceptedTransports.HasFlag(CredentialTransport.CustomHeader))
			.Select(c => c.HeaderName)
			.ToHashSet(StringComparer.OrdinalIgnoreCase);

}
