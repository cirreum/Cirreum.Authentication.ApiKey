namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Provides validation utilities for API keys that can be shared across resolvers.
/// </summary>
public interface IApiKeyValidator {

	/// <summary>
	/// Validates the format of an API key (length, characters, entropy floor).
	/// </summary>
	/// <param name="key">The key to validate.</param>
	/// <param name="profile">The per-store conformance profile to enforce, or <see langword="null"/> to
	/// use the provider-level profile. Determines the effective entropy floor (ADR-0020 §4).</param>
	/// <returns>A result indicating whether the format is valid.</returns>
	ApiKeyFormatValidationResult ValidateFormat(string key, ApiKeyConformanceProfile? profile = null);

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
	/// <param name="profile">The per-store conformance profile to enforce, or <see langword="null"/> to
	/// use the provider-level profile. Determines whether a missing expiry is rejected (ADR-0020 §4).</param>
	/// <returns><see langword="true"/> if the key has expired; otherwise, <see langword="false"/>.</returns>
	bool IsExpired(DateTimeOffset? expiresAt, TimeSpan? gracePeriod = null, ApiKeyConformanceProfile? profile = null);

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
	/// Verifies a presented key against a stored hash, in constant time. Self-describing encoded
	/// hashes (from <see cref="HashKeyEncoded"/>) are dispatched to the matching hasher; legacy
	/// bare hashes fall back to <see cref="ValidateKeyHash"/> with the supplied <paramref name="salt"/>.
	/// </summary>
	/// <param name="providedKey">The key provided in the request.</param>
	/// <param name="storedHash">The stored hash (self-describing or legacy bare).</param>
	/// <param name="salt">The legacy salt. It is <b>required</b> when <paramref name="storedHash"/> is a
	/// legacy bare hash (passing <see langword="null"/> there will fail verification) and is
	/// <b>ignored</b> when <paramref name="storedHash"/> is a self-describing hash (the salt is embedded).</param>
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
