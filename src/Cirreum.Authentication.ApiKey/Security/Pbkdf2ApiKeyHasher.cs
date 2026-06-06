namespace Cirreum.Authentication.ApiKey;

using System.Security.Cryptography;
using System.Text;

/// <summary>
/// PBKDF2 (HMAC-SHA256) <see cref="IApiKeyHasher"/> (NIST SP 800-132). Encoded form:
/// <c>pbkdf2${iterations}${saltB64}${hashB64}</c>. The iteration count is stored with the hash so
/// the work factor can be raised over time without breaking verification of existing keys.
/// </summary>
public sealed class Pbkdf2ApiKeyHasher : IApiKeyHasher {

	private const string Prefix = "pbkdf2";
	private const int SaltByteCount = 32;
	private const int HashByteCount = 32;

	// Encoded salt/hash parts are ~44 base64 chars (32 bytes); this caps decode allocation and
	// prevents integer overflow in the buffer-size calculation for pathological inputs.
	private const int MaxBase64PartLength = 256;

	/// <summary>OWASP-aligned default iteration count for PBKDF2-HMAC-SHA256.</summary>
	public const int DefaultIterations = 600_000;

	/// <summary>
	/// Defense-in-depth ceiling on the iteration count. Verification rejects any stored hash whose
	/// embedded iteration count exceeds this, so a poisoned/hostile store value cannot amplify the
	/// per-verify work into a CPU denial-of-service. Generous headroom above legitimate work factors.
	/// </summary>
	public const int MaxIterations = 10_000_000;

	private readonly int _iterations;

	/// <summary>
	/// Creates a PBKDF2 hasher.
	/// </summary>
	/// <param name="iterations">The work factor for newly hashed keys. Verification uses the
	/// iteration count stored in the encoded hash, so lowering this does not break existing keys.</param>
	public Pbkdf2ApiKeyHasher(int iterations = DefaultIterations) {
		ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(iterations, MaxIterations);
		this._iterations = iterations;
	}

	/// <inheritdoc />
	public ApiKeyHashAlgorithm Algorithm => ApiKeyHashAlgorithm.Pbkdf2;

	/// <inheritdoc />
	public string Hash(string apiKey) {
		ArgumentException.ThrowIfNullOrEmpty(apiKey);

		var salt = new byte[SaltByteCount];
		RandomNumberGenerator.Fill(salt);

		var hash = Derive(apiKey, salt, this._iterations);

		return $"{Prefix}${this._iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
	}

	/// <inheritdoc />
	public bool Verify(string apiKey, string encodedHash) {
		if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(encodedHash)) {
			return false;
		}

		var parts = encodedHash.Split('$');
		if (parts.Length != 4 || parts[0] != Prefix) {
			return false;
		}

		if (!int.TryParse(parts[1], out var iterations) || iterations < 1 || iterations > MaxIterations) {
			return false;
		}

		if (!TryFromBase64(parts[2], out var salt) || !TryFromBase64(parts[3], out var expected)) {
			return false;
		}

		if (salt.Length != SaltByteCount || expected.Length != HashByteCount) {
			return false;
		}

		var actual = Derive(apiKey, salt, iterations);
		return CryptographicOperations.FixedTimeEquals(actual, expected);
	}

	private static byte[] Derive(string apiKey, byte[] salt, int iterations) {
		var keyBytes = Encoding.UTF8.GetBytes(apiKey);

		try {
			return Rfc2898DeriveBytes.Pbkdf2(
				keyBytes,
				salt,
				iterations,
				HashAlgorithmName.SHA256,
				HashByteCount);
		} finally {
			CryptographicOperations.ZeroMemory(keyBytes);
		}
	}

	private static bool TryFromBase64(string value, out byte[] bytes) {
		if (value.Length > MaxBase64PartLength) {
			bytes = [];
			return false;
		}

		var buffer = new byte[((value.Length + 3) / 4) * 3];
		if (Convert.TryFromBase64String(value, buffer, out var written)) {
			bytes = buffer[..written];
			return true;
		}

		bytes = [];
		return false;
	}

}
