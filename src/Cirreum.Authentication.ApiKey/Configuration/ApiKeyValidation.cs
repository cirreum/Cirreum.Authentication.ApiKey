namespace Cirreum.Authentication.Configuration;

internal static class ApiKeyValidation {

	private static readonly Dictionary<string, string> processedApiKeys = [];

	/// <summary>
	/// Validates that the API key is unique across all registered clients.
	/// </summary>
	/// <param name="apiKey">The API key to validate.</param>
	/// <param name="instanceKey">The instance key for error messaging.</param>
	/// <param name="clientId">The client ID being registered.</param>
	/// <exception cref="InvalidOperationException">
	/// Thrown when the same API key is used by multiple client instances.
	/// </exception>
	public static void ValidateApiKeyUniqueness(
		string apiKey,
		string instanceKey,
		string clientId) {

		var keyHash = GetKeyHash(apiKey);
		var registrationKey = $"Cirreum.Authorization.ApiKey:{keyHash}";

		if (!processedApiKeys.TryAdd(registrationKey, clientId)) {
			throw new InvalidOperationException(
				$"API key for instance '{instanceKey}' is already registered to client '{processedApiKeys[registrationKey]}'. " +
				$"Cannot register the same key with multiple clients.");
		}
	}

	private static string GetKeyHash(string apiKey) {
		var bytes = System.Text.Encoding.UTF8.GetBytes(apiKey);
		var hash = System.Security.Cryptography.SHA256.HashData(bytes);
		return Convert.ToBase64String(hash);
	}

}