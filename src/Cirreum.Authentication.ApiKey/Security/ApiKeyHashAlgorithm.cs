namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// The stored-secret hash algorithm for dynamic (database-backed) API keys (ADR-0020 §3).
/// Static Key-Vault keys are protected at rest by the vault and compared in-memory, so the
/// hashing knob applies to the dynamic model only.
/// </summary>
public enum ApiKeyHashAlgorithm {

	/// <summary>
	/// Salted SHA-256. Compliant for look-up secrets at or above 112 bits of entropy
	/// (NIST SP 800-63B §5.1.2); the default, preserving today's behavior.
	/// </summary>
	Sha256 = 0,

	/// <summary>
	/// PBKDF2 (HMAC-SHA256, NIST SP 800-132). Offered for stored secrets below the entropy
	/// floor, where a work-factored KDF is warranted.
	/// </summary>
	Pbkdf2 = 1

}
