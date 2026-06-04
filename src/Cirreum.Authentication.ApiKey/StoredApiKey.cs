namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Represents a stored API key retrieved from a database or external source.
/// Used by <see cref="DynamicApiKeyClientResolver"/> to standardize key storage formats.
/// </summary>
public record StoredApiKey {

	/// <summary>
	/// Gets the unique identifier for this client.
	/// </summary>
	public required string ClientId { get; init; }

	/// <summary>
	/// Gets the display name for this client.
	/// </summary>
	public required string ClientName { get; init; }

	/// <summary>
	/// Gets the hashed API key value.
	/// Use <see cref="IApiKeyValidator.HashKey"/> to generate this value.
	/// </summary>
	public required string KeyHash { get; init; }

	/// <summary>
	/// Gets the salt used when hashing the key, if applicable.
	/// </summary>
	public string? Salt { get; init; }

	/// <summary>
	/// Gets the HTTP header name this key is associated with.
	/// </summary>
	public required string HeaderName { get; init; }

	/// <summary>
	/// Gets the roles assigned to this client.
	/// </summary>
	public IReadOnlyList<string> Roles { get; init; } = [];

	/// <summary>
	/// Gets the optional expiration time for this key.
	/// </summary>
	public DateTimeOffset? ExpiresAt { get; init; }

	/// <summary>
	/// Gets optional custom claims to include in the client's identity.
	/// </summary>
	public IReadOnlyDictionary<string, string>? Claims { get; init; }

	/// <summary>
	/// Converts this stored key to an <see cref="ApiKeyClient"/> for authentication.
	/// </summary>
	/// <returns>An API key client with the stored key's properties.</returns>
	public ApiKeyClient ToApiKeyClient() => new() {
		ClientId = this.ClientId,
		ClientName = this.ClientName,
		Roles = this.Roles,
		ExpiresAt = this.ExpiresAt,
		Claims = this.Claims
	};

}