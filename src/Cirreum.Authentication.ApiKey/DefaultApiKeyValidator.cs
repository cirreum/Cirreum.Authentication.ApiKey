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
public sealed class DefaultApiKeyValidator(
	IOptions<ApiKeyValidationOptions> options
) : IApiKeyValidator {

	private readonly ApiKeyValidationOptions _options = options.Value;

	/// <inheritdoc/>
	public ApiKeyFormatValidationResult ValidateFormat(string key) {
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
	public bool IsExpired(DateTimeOffset? expiresAt, TimeSpan? gracePeriod = null) {
		if (this._options.AllowExpiredKeys) {
			return false;
		}

		if (expiresAt is null) {
			return false;
		}

		var effectiveGracePeriod = gracePeriod ?? this._options.ExpirationGracePeriod;
		var effectiveExpiration = expiresAt.Value.Add(effectiveGracePeriod);

		return DateTimeOffset.UtcNow > effectiveExpiration;
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

	/// <summary>
	/// Generates a cryptographically secure random salt.
	/// </summary>
	private static string GenerateSalt() {
		var saltBytes = new byte[32];
		RandomNumberGenerator.Fill(saltBytes);
		return Convert.ToBase64String(saltBytes);
	}

}