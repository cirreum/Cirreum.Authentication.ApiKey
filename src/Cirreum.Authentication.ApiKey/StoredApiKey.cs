namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;

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
	/// Gets the hashed API key value — a self-describing encoded hash (PHC-style <c>{algorithm}$…$salt$hash</c>).
	/// Use <see cref="IApiKeyValidator.HashKeyEncoded"/> to generate this value; verification dispatches on
	/// the encoded algorithm tag and fails closed on any non-self-describing value.
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

	// ---- Per-key overrides (ADR-0020 §9) — captured at key creation, may only tighten ----------

	/// <summary>
	/// Gets the time this key was created. Required to enforce <see cref="MaxKeyAge"/>
	/// (the NIST SP 800-57 cryptoperiod).
	/// </summary>
	public DateTimeOffset? CreatedAt { get; init; }

	/// <summary>
	/// Gets an optional per-key maximum age (cryptoperiod). It may only <em>tighten</em> the active
	/// provider cap: the effective max age is the shorter of this and the configured
	/// <c>ApiKeyValidationOptions.MaxKeyAge</c>. Enforced against <see cref="CreatedAt"/>.
	/// </summary>
	public TimeSpan? MaxKeyAge { get; init; }

	/// <summary>
	/// Gets optional per-key scopes, surfaced as <c>scope</c> claims on the authenticated identity.
	/// </summary>
	public IReadOnlyList<string>? Scopes { get; init; }

	/// <summary>
	/// Converts this stored key to an <see cref="ApiKeyClient"/> for authentication, accepted on the
	/// transport it was presented (and matched) on.
	/// </summary>
	/// <param name="acceptedTransport">The transport the credential arrived on. The presented key has
	/// already matched this stored secret on this transport, so it is by definition accepted on it; this
	/// is threaded onto <see cref="ApiKeyClient.AcceptedTransports"/> so the handler's transport gate does
	/// not reject a dynamic-store key presented on a custom header (M4). A dynamic store that wants to
	/// pin specific transports per key can do so in its own lookup; the default is "accept where matched".</param>
	/// <returns>An API key client with the stored key's properties.</returns>
	public ApiKeyClient ToApiKeyClient(CredentialTransport acceptedTransport) => new() {
		ClientId = this.ClientId,
		ClientName = this.ClientName,
		Roles = this.Roles,
		AcceptedTransports = acceptedTransport,
		ExpiresAt = this.ExpiresAt,
		CreatedAt = this.CreatedAt,
		MaxKeyAge = this.MaxKeyAge,
		Claims = this.Claims,
		Scopes = this.Scopes ?? []
	};

}