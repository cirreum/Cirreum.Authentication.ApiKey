namespace Cirreum.Authentication.ApiKey;

using Cirreum.Authentication.Configuration;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Default implementation of <see cref="IApiKeyValidator"/> providing secure
/// validation utilities for API keys.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="DefaultApiKeyValidator"/> class.
/// </remarks>
/// <param name="options">The validation options.</param>
/// <param name="hashers">The registered self-describing hashers (e.g. SHA-256, PBKDF2) used by
/// <see cref="HashKeyEncoded"/> / <see cref="VerifyKey"/>. May be empty when only the legacy
/// salted-SHA-256 path is in use.</param>
public sealed class DefaultApiKeyValidator(
	IOptions<ApiKeyValidationOptions> options,
	IEnumerable<IApiKeyHasher> hashers
) : IApiKeyValidator {

	private readonly ApiKeyValidationOptions _options = options.Value;
	private readonly IApiKeyHasher[] _hashers = hashers as IApiKeyHasher[] ?? [.. hashers];

	/// <inheritdoc/>
	public ApiKeyFormatValidationResult ValidateFormat(string key, ApiKeyConformanceProfile? profile = null) {
		if (string.IsNullOrWhiteSpace(key)) {
			return ApiKeyFormatValidationResult.Invalid("API key cannot be empty");
		}

		if (key.Length < this._options.MinimumKeyLength) {
			return ApiKeyFormatValidationResult.Invalid(
				$"API key must be at least {this._options.MinimumKeyLength} characters");
		}

		if (key.Length > this._options.MaximumKeyLength) {
			return ApiKeyFormatValidationResult.Invalid(
				$"API key cannot exceed {this._options.MaximumKeyLength} characters");
		}

		if (this._options.EnforceValidCharacters) {
			var validChars = this._options.ValidCharacters.ToHashSet();
			foreach (var c in key) {
				if (!validChars.Contains(c)) {
					return ApiKeyFormatValidationResult.Invalid(
						$"API key contains invalid character: '{c}'");
				}
			}
		}

		var entropyFloor = this._options.EffectiveMinimumEntropyBitsFor(profile ?? this._options.ConformanceProfile);
		if (entropyFloor > 0 && ApiKeyEntropyEstimator.EstimateBits(key) < entropyFloor) {
			return ApiKeyFormatValidationResult.Invalid(
				$"API key does not meet the required minimum entropy of {entropyFloor} bits");
		}

		return ApiKeyFormatValidationResult.Valid();
	}

	/// <inheritdoc/>
	public bool CompareKeysSecurely(string providedKey, string expectedKey) {
		if (string.IsNullOrEmpty(providedKey) || string.IsNullOrEmpty(expectedKey)) {
			return false;
		}

		var providedByteCount = Encoding.UTF8.GetByteCount(providedKey);
		var expectedByteCount = Encoding.UTF8.GetByteCount(expectedKey);

		// Use stackalloc for reasonable key sizes, fall back to array for larger keys
		const int StackAllocThreshold = 256;

		if (providedByteCount <= StackAllocThreshold && expectedByteCount <= StackAllocThreshold) {
			Span<byte> providedBytes = stackalloc byte[providedByteCount];
			Span<byte> expectedBytes = stackalloc byte[expectedByteCount];

			Encoding.UTF8.GetBytes(providedKey, providedBytes);
			Encoding.UTF8.GetBytes(expectedKey, expectedBytes);

			return this.CompareKeysSecurely(providedBytes, expectedBytes);
		}

		// Fall back to heap allocation for very large keys
		return this.CompareKeysSecurely(
			Encoding.UTF8.GetBytes(providedKey),
			Encoding.UTF8.GetBytes(expectedKey));
	}

	/// <inheritdoc/>
	public bool CompareKeysSecurely(ReadOnlySpan<byte> providedKey, ReadOnlySpan<byte> expectedKey) {
		if (providedKey.IsEmpty || expectedKey.IsEmpty) {
			return false;
		}

		return CryptographicOperations.FixedTimeEquals(providedKey, expectedKey);
	}

	/// <inheritdoc/>
	public bool ValidateKeyHash(string providedKey, string storedHash, string? salt = null) {
		if (string.IsNullOrEmpty(providedKey) || string.IsNullOrEmpty(storedHash)) {
			return false;
		}

		var computedHash = this.HashKey(providedKey, salt);
		return this.CompareKeysSecurely(computedHash.Hash, storedHash);
	}

	/// <inheritdoc/>
	public bool IsExpired(DateTimeOffset? expiresAt, TimeSpan? gracePeriod = null, ApiKeyConformanceProfile? profile = null) {
		if (this._options.AllowExpiredKeys) {
			return false;
		}

		if (expiresAt is null) {
			// A key with no expiry is rejected (treated as expired) when the profile/knob requires one.
			return this._options.EffectiveRequireExpiryFor(profile ?? this._options.ConformanceProfile);
		}

		var effectiveGracePeriod = gracePeriod ?? this._options.ExpirationGracePeriod;
		var effectiveExpiration = expiresAt.Value.Add(effectiveGracePeriod);

		return DateTimeOffset.UtcNow > effectiveExpiration;
	}

	/// <inheritdoc/>
	public bool IsBeyondMaxAge(DateTimeOffset? createdAt, TimeSpan? perKeyMaxAge = null) {
		if (this._options.AllowExpiredKeys) {
			return false;
		}

		// Tighten-only: the effective cap is the shorter of the configured and per-key max ages.
		var effectiveMaxAge = MinTimeSpan(this._options.MaxKeyAge, perKeyMaxAge);
		if (effectiveMaxAge is null || createdAt is null) {
			return false;
		}

		return DateTimeOffset.UtcNow > createdAt.Value.Add(effectiveMaxAge.Value);
	}

	private static TimeSpan? MinTimeSpan(TimeSpan? a, TimeSpan? b) {
		if (a is null) {
			return b;
		}

		if (b is null) {
			return a;
		}

		return a.Value <= b.Value ? a : b;
	}

	/// <inheritdoc/>
	public ApiKeyHashResult HashKey(string key, string? salt = null) {
		ArgumentException.ThrowIfNullOrWhiteSpace(key);

		// Generate salt if not provided
		salt ??= GenerateSalt();

		// Combine key and salt
		var combined = $"{salt}{key}";
		var bytes = Encoding.UTF8.GetBytes(combined);

		// Use SHA256 for hashing
		var hashBytes = SHA256.HashData(bytes);
		var hash = Convert.ToBase64String(hashBytes);

		return new ApiKeyHashResult(hash, salt);
	}

	/// <inheritdoc/>
	public string HashKeyEncoded(string key) {
		ArgumentException.ThrowIfNullOrWhiteSpace(key);
		return this.SelectHasher(this._options.HashAlgorithm).Hash(key);
	}

	/// <inheritdoc/>
	public bool VerifyKey(string providedKey, string storedHash, string? salt = null) {
		if (string.IsNullOrEmpty(providedKey) || string.IsNullOrEmpty(storedHash)) {
			return false;
		}

		return IsSelfDescribingHash(storedHash)
			? this.VerifyHashedKey(providedKey, storedHash)
			: this.ValidateKeyHash(providedKey, storedHash, salt);
	}

	private bool VerifyHashedKey(string providedKey, string encodedHash) {
		foreach (var hasher in this._hashers) {
			if (hasher.Verify(providedKey, encodedHash)) {
				return true;
			}
		}

		return false;
	}

	private IApiKeyHasher SelectHasher(ApiKeyHashAlgorithm algorithm) {
		foreach (var hasher in this._hashers) {
			if (hasher.Algorithm == algorithm) {
				return hasher;
			}
		}

		throw new InvalidOperationException(
			$"No {nameof(IApiKeyHasher)} is registered for algorithm '{algorithm}'. " +
			"Register the ApiKey scheme via AddApiKey(...), which registers the built-in hashers.");
	}

	private static bool IsSelfDescribingHash(string storedHash) =>
		storedHash.StartsWith("sha256$", StringComparison.Ordinal) ||
		storedHash.StartsWith("pbkdf2$", StringComparison.Ordinal);

	/// <summary>
	/// Generates a cryptographically secure random salt.
	/// </summary>
	private static string GenerateSalt() {
		var saltBytes = new byte[32];
		RandomNumberGenerator.Fill(saltBytes);
		return Convert.ToBase64String(saltBytes);
	}

}