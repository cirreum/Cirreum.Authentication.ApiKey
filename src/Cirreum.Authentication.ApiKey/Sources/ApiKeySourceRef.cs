namespace Cirreum.Authentication.ApiKey;

using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Derives the opaque, wire-facing store reference (<c>X-Api-Source</c> value) for a key set from
/// its code-given friendly name (ADR-0020 §6). The derivation is a pure, deterministic function —
/// computed identically at boot and at key issuance — so the friendly name never reaches the wire,
/// and routing carries no persisted state. Never uses <c>string.GetHashCode()</c> (per-process
/// randomized); the result is stable across heads and processes.
/// </summary>
public static class ApiKeySourceRef {

	private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

	/// <summary>The number of leading hash bytes encoded (10 bytes = 80 bits = 16 Base32 chars).</summary>
	private const int RefBytes = 10;

	/// <summary>
	/// Derives the opaque source reference for a friendly name. Plain <c>SHA-256</c> by default
	/// (a routing-only signal, so unguessability is not required); pass an <paramref name="hmacKey"/>
	/// (an app secret) to make the reference unguessable from the name via <c>HMAC-SHA256</c>.
	/// </summary>
	/// <param name="friendlyName">The code-given store name.</param>
	/// <param name="hmacKey">Optional HMAC key; when empty, plain SHA-256 is used.</param>
	/// <returns>A 16-character uppercase Base32 reference.</returns>
	public static string Derive(string friendlyName, ReadOnlySpan<byte> hmacKey = default) {
		ArgumentException.ThrowIfNullOrWhiteSpace(friendlyName);

		var nameBytes = Encoding.UTF8.GetBytes(friendlyName);
		Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];

		if (hmacKey.IsEmpty) {
			SHA256.HashData(nameBytes, hash);
		} else {
			HMACSHA256.HashData(hmacKey, nameBytes, hash);
		}

		return Base32Encode(hash[..RefBytes]);
	}

	private static string Base32Encode(ReadOnlySpan<byte> data) {
		var output = new char[(data.Length * 8 + 4) / 5];
		var bitBuffer = 0;
		var bitCount = 0;
		var index = 0;

		foreach (var b in data) {
			bitBuffer = (bitBuffer << 8) | b;
			bitCount += 8;
			while (bitCount >= 5) {
				bitCount -= 5;
				output[index++] = Base32Alphabet[(bitBuffer >> bitCount) & 0x1F];
			}
		}

		if (bitCount > 0) {
			output[index++] = Base32Alphabet[(bitBuffer << (5 - bitCount)) & 0x1F];
		}

		return new string(output, 0, index);
	}

}
