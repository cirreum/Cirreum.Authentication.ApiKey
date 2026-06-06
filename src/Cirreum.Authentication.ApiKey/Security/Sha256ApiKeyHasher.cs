namespace Cirreum.Authentication.ApiKey;

using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Salted SHA-256 <see cref="IApiKeyHasher"/>. Encoded form: <c>sha256${saltB64}${hashB64}</c>,
/// where the hash is <c>SHA-256(salt-bytes ‖ key-bytes)</c>. Intended for high-entropy API keys /
/// lookup secrets; not suitable for user-chosen passwords.
/// </summary>
public sealed class Sha256ApiKeyHasher : IApiKeyHasher {

	private const string Prefix = "sha256";
	private const int SaltByteCount = 32;

	// Encoded salt/hash parts are ~44 base64 chars (32 bytes); this caps decode allocation and
	// prevents integer overflow in the buffer-size calculation for pathological inputs.
	private const int MaxBase64PartLength = 256;

	/// <inheritdoc />
	public ApiKeyHashAlgorithm Algorithm => ApiKeyHashAlgorithm.Sha256;

	/// <inheritdoc />
	public string Hash(string apiKey) {
		ArgumentException.ThrowIfNullOrEmpty(apiKey);

		var salt = new byte[SaltByteCount];
		RandomNumberGenerator.Fill(salt);

		var hash = ComputeHash(apiKey, salt);

		return $"{Prefix}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
	}

	/// <inheritdoc />
	public bool Verify(string apiKey, string encodedHash) {
		if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(encodedHash)) {
			return false;
		}

		var parts = encodedHash.Split('$');
		if (parts.Length != 3 || parts[0] != Prefix) {
			return false;
		}

		if (!TryFromBase64(parts[1], out var salt) || !TryFromBase64(parts[2], out var expected)) {
			return false;
		}

		if (salt.Length != SaltByteCount || expected.Length != SHA256.HashSizeInBytes) {
			return false;
		}

		var actual = ComputeHash(apiKey, salt);
		return CryptographicOperations.FixedTimeEquals(actual, expected);
	}

	private static byte[] ComputeHash(string apiKey, byte[] salt) {
		var keyBytes = Encoding.UTF8.GetBytes(apiKey);
		var combined = new byte[salt.Length + keyBytes.Length];

		try {
			Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
			Buffer.BlockCopy(keyBytes, 0, combined, salt.Length, keyBytes.Length);
			return SHA256.HashData(combined);
		} finally {
			CryptographicOperations.ZeroMemory(keyBytes);
			CryptographicOperations.ZeroMemory(combined);
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
