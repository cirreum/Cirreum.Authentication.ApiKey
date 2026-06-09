namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Provides validation utilities for API keys that can be shared across resolvers.
/// </summary>
public interface IApiKeyValidator {

	/// <summary>
	/// Validates the request-time format of a presented API key (length and allowed characters only).
	/// Entropy is NOT checked here — it is a key-issuance concern (enforced for Form-1 configured keys at
	/// startup via <see cref="ValidateConfiguredKeyStrength"/>, and guaranteed by construction for Form-2
	/// managed keys). Checking entropy against a presented credential would be a structural oracle.
	/// </summary>
	/// <param name="key">The presented key to validate.</param>
	/// <returns>A result indicating whether the format is valid.</returns>
	ApiKeyFormatValidationResult ValidateFormat(string key);

	/// <summary>
	/// Validates that a Form-1 <em>statically configured</em> key meets the strength floor (length, allowed
	/// characters, and <see cref="ApiKeyValidationOptions.MinimumKeyEntropyBits"/>). Called at startup by the
	/// registrar; bypass with <see cref="ApiKeyValidationOptions.AllowWeakConfiguredKeys"/> for demos.
	/// </summary>
	/// <param name="key">The configured key to validate.</param>
	/// <returns>A result indicating whether the configured key is strong enough.</returns>
	ApiKeyFormatValidationResult ValidateConfiguredKeyStrength(string key);

	/// <summary>
	/// Performs a constant-time comparison of two keys to prevent timing attacks.
	/// Use this for plain-text key comparison.
	/// </summary>
	/// <param name="providedKey">The key provided in the request.</param>
	/// <param name="expectedKey">The expected key value.</param>
	/// <returns><see langword="true"/> if the keys match; otherwise, <see langword="false"/>.</returns>
	bool CompareKeysSecurely(string providedKey, string expectedKey);

	/// <summary>
	/// Performs a constant-time comparison of two keys to prevent timing attacks.
	/// Use this overload for allocation-free comparison when keys are already encoded as bytes.
	/// </summary>
	/// <param name="providedKey">The key provided in the request as UTF-8 bytes.</param>
	/// <param name="expectedKey">The expected key value as UTF-8 bytes.</param>
	/// <returns><see langword="true"/> if the keys match; otherwise, <see langword="false"/>.</returns>
	bool CompareKeysSecurely(ReadOnlySpan<byte> providedKey, ReadOnlySpan<byte> expectedKey);

	/// <summary>
	/// Validates a provided key against a stored hash.
	/// Use this for hashed key storage (recommended for database storage).
	/// </summary>
	/// <param name="providedKey">The key provided in the request.</param>
	/// <param name="storedHash">The stored hash to compare against.</param>
	/// <param name="salt">Optional salt used in hashing.</param>
	/// <returns><see langword="true"/> if the key matches the hash; otherwise, <see langword="false"/>.</returns>
	bool ValidateKeyHash(string providedKey, string storedHash, string? salt = null);

	/// <summary>
	/// Checks whether an API key has expired.
	/// </summary>
	/// <param name="expiresAt">The expiration time, or <see langword="null"/> if no expiration.</param>
	/// <param name="gracePeriod">Optional grace period to allow after expiration.</param>
	/// <returns><see langword="true"/> if the key has expired; otherwise, <see langword="false"/>. A missing
	/// expiry is treated as expired when <see cref="ApiKeyValidationOptions.RequireExpiry"/> is set.</returns>
	bool IsExpired(DateTimeOffset? expiresAt, TimeSpan? gracePeriod = null);

	/// <summary>
	/// Checks whether a key has exceeded its maximum age / cryptoperiod (NIST SP 800-57), measured from
	/// <paramref name="createdAt"/>. The effective max age is the <em>shorter</em> (tighten-only) of the
	/// configured <c>ApiKeyValidationOptions.MaxKeyAge</c> and the per-key
	/// <paramref name="perKeyMaxAge"/>. Returns <see langword="false"/> when neither cap is set or
	/// <paramref name="createdAt"/> is unknown.
	/// </summary>
	/// <param name="createdAt">When the key was created.</param>
	/// <param name="perKeyMaxAge">An optional per-key max-age override (may only tighten the configured cap).</param>
	/// <returns><see langword="true"/> if the key is older than the effective max age.</returns>
	bool IsBeyondMaxAge(DateTimeOffset? createdAt, TimeSpan? perKeyMaxAge = null);

	/// <summary>
	/// Generates a secure hash for storing an API key.
	/// </summary>
	/// <param name="key">The key to hash.</param>
	/// <param name="salt">Optional salt to use (generated if not provided).</param>
	/// <returns>The hash result containing the hash and salt used.</returns>
	ApiKeyHashResult HashKey(string key, string? salt = null);

	/// <summary>
	/// Hashes an API key into a self-describing encoded string (PHC-style
	/// <c>{algorithm}$…$salt$hash</c>) using the configured <see cref="ApiKeyValidationOptions.HashAlgorithm"/>.
	/// The algorithm and parameters travel with the value, so verification and work-factor rotation
	/// need no out-of-band metadata. Recommended for new dynamic (database-backed) keys.
	/// </summary>
	/// <param name="key">The raw key to hash.</param>
	/// <returns>A self-describing encoded hash.</returns>
	string HashKeyEncoded(string key);

	/// <summary>
	/// Verifies a presented key against a stored, self-describing encoded hash (from
	/// <see cref="HashKeyEncoded"/>), in constant time, dispatching to the hasher named by the encoded
	/// algorithm tag. A stored value that is NOT self-describing is rejected (fail closed) — the legacy
	/// bare-SHA-256 path is no longer accepted; managed stores must persist <see cref="HashKeyEncoded"/> output.
	/// </summary>
	/// <param name="providedKey">The key provided in the request.</param>
	/// <param name="storedHash">The self-describing stored hash (e.g. <c>sha256$…</c> / <c>pbkdf2$…</c>).</param>
	/// <param name="salt">Ignored (the salt is embedded in a self-describing hash). Retained for back-compat.</param>
	/// <returns><see langword="true"/> if the key matches; otherwise <see langword="false"/>.</returns>
	bool VerifyKey(string providedKey, string storedHash, string? salt = null);
}

/// <summary>
/// Result of API key format validation.
/// </summary>
/// <param name="IsValid">Whether the format is valid.</param>
/// <param name="ErrorReason">The reason for invalidity, if applicable.</param>
public readonly record struct ApiKeyFormatValidationResult(bool IsValid, string? ErrorReason) {

	/// <summary>
	/// Creates a valid result.
	/// </summary>
	public static ApiKeyFormatValidationResult Valid() => new(true, null);

	/// <summary>
	/// Creates an invalid result with a reason.
	/// </summary>
	/// <param name="reason">The reason the format is invalid.</param>
	public static ApiKeyFormatValidationResult Invalid(string reason) => new(false, reason);
}

/// <summary>
/// Result of hashing an API key.
/// </summary>
/// <param name="Hash">The computed hash.</param>
/// <param name="Salt">The salt used in hashing.</param>
public readonly record struct ApiKeyHashResult(string Hash, string Salt);
