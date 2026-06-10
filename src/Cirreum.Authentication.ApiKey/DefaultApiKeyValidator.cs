namespace Cirreum.Authentication.ApiKey;

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
/// <see cref="HashKeyEncoded"/> / <see cref="VerifyKey"/>.</param>
public sealed class DefaultApiKeyValidator(
	IOptions<ApiKeyValidationOptions> options,
	IEnumerable<IApiKeyHasher> hashers
) : IApiKeyValidator {

	private readonly ApiKeyValidationOptions _options = options.Value;
	private readonly IApiKeyHasher[] _hashers = hashers as IApiKeyHasher[] ?? [.. hashers];

	// Built once from the (singleton, bound) options rather than per ValidateFormat call on the hot path.
	private readonly HashSet<char> _validCharacters = [.. options.Value.ValidCharacters];

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
			foreach (var c in key) {
				if (!this._validCharacters.Contains(c)) {
					return ApiKeyFormatValidationResult.Invalid(
						$"API key contains invalid character: '{c}'");
				}
			}
		}

		// Entropy is deliberately NOT checked against a presented credential — that would be a structural
		// oracle. Form-1 configured keys are strength-checked at startup (ValidateConfiguredKeyStrength);
		// Form-2 managed keys are strong by construction.
		return ApiKeyFormatValidationResult.Valid();
	}

	/// <inheritdoc/>
	public ApiKeyFormatValidationResult ValidateConfiguredKeyStrength(string key) {
		var format = this.ValidateFormat(key);
		if (!format.IsValid) {
			return format;
		}

		var floor = this._options.MinimumKeyEntropyBits;
		if (floor > 0 && ApiKeyEntropyEstimator.EstimateBits(key) < floor) {
			return ApiKeyFormatValidationResult.Invalid(
				$"Configured API key does not meet the {floor}-bit minimum strength floor");
		}

		return ApiKeyFormatValidationResult.Valid();
	}

	/// <inheritdoc/>
	public bool CompareKeysSecurely(string providedKey, string expectedKey) {
		if (string.IsNullOrEmpty(providedKey) || string.IsNullOrEmpty(expectedKey)) {
			return false;
		}

		// Self-defending upper bound on the PRESENTED key: a public timing-safe API must not allocate
		// proportional to an unbounded caller-supplied value (N14). A key longer than the configured maximum
		// is invalid by policy and cannot match, so returning false early is correct (the expected key is
		// trusted/configured and is not bounded here).
		if (providedKey.Length > this._options.MaximumKeyLength) {
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
	public bool IsExpired(DateTimeOffset? expiresAt, TimeSpan? gracePeriod = null) {
		if (this._options.AllowExpiredKeys) {
			return false;
		}

		if (expiresAt is null) {
			// A key with no expiry is rejected (treated as expired) when RequireExpiry is set.
			return this._options.RequireExpiry;
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
	public string HashKeyEncoded(string key) {
		ArgumentException.ThrowIfNullOrWhiteSpace(key);
		return this.SelectHasher(this._options.HashAlgorithm).Hash(key);
	}

	/// <inheritdoc/>
	public bool VerifyKey(string providedKey, string storedHash, string? salt = null) {
		if (string.IsNullOrEmpty(providedKey) || string.IsNullOrEmpty(storedHash)) {
			return false;
		}

		// Dispatch to the single hasher named by the encoded algorithm tag ("{algorithm}$..."). A stored
		// value with no recognized tag is rejected (fail closed): the legacy bare-SHA-256 path — salt-
		// optional, single-round, entropy-ungated — is no longer accepted; managed stores persist
		// HashKeyEncoded(...) output. Dispatching to exactly one hasher (rather than trying all) also
		// forecloses algorithm confusion should a future hasher's Verify ever be lenient about a foreign tag.
		var separator = storedHash.IndexOf('$');
		if (separator <= 0 || !EncodedAlgorithmTags.TryGetValue(storedHash[..separator], out var algorithm)) {
			return false;
		}

		foreach (var hasher in this._hashers) {
			if (hasher.Algorithm == algorithm) {
				return hasher.Verify(providedKey, storedHash);
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

	// Maps each self-describing encoded prefix to its algorithm, so VerifyKey dispatches to exactly one hasher.
	private static readonly Dictionary<string, ApiKeyHashAlgorithm> EncodedAlgorithmTags = new(StringComparer.Ordinal) {
		["sha256"] = ApiKeyHashAlgorithm.Sha256,
		["pbkdf2"] = ApiKeyHashAlgorithm.Pbkdf2,
	};

}