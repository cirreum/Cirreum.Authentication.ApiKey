namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Hashes and verifies stored API key secrets for the dynamic (database-backed) model (ADR-0020 §3).
/// Implementations produce a self-describing, PHC-style encoded string
/// (<c>{algorithm}${parameters...}${salt}${hash}</c>) so the algorithm and parameters travel with
/// the stored value — enabling verification and rotation without out-of-band metadata.
/// </summary>
/// <remarks>
/// This is the extension seam for custom hashing. The built-in implementations are
/// <see cref="Sha256ApiKeyHasher"/> and <see cref="Pbkdf2ApiKeyHasher"/>.
/// </remarks>
public interface IApiKeyHasher {

	/// <summary>The algorithm this hasher produces.</summary>
	ApiKeyHashAlgorithm Algorithm { get; }

	/// <summary>
	/// Hashes a raw API key secret into a self-describing encoded string suitable for storage.
	/// </summary>
	string Hash(string apiKey);

	/// <summary>
	/// Verifies a raw API key secret against a previously produced encoded hash, in constant time.
	/// Returns <see langword="false"/> if the encoded value is not in this hasher's format.
	/// </summary>
	bool Verify(string apiKey, string encodedHash);

}
