namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Generates high-entropy API key secrets (ADR-0020 §3). The generator — not the heuristic
/// entropy estimator — is the real mitigation for weak keys: generate, don't hand-pick.
/// </summary>
public interface IApiKeyGenerator {

	/// <summary>
	/// Generates a cryptographically random, URL-safe API key secret (the raw <c>{secret}</c>
	/// portion; scheme/environment prefixing such as <c>ak_{env}_</c> is applied by the registrar).
	/// </summary>
	/// <param name="entropyBits">The target entropy in bits. Defaults to 256; values below the
	/// NIST SP 800-63B §5.1.2 look-up-secret floor (112) are raised to it.</param>
	/// <returns>A URL-safe secret string with at least <paramref name="entropyBits"/> of entropy.</returns>
	string Generate(int entropyBits = 256);

}
