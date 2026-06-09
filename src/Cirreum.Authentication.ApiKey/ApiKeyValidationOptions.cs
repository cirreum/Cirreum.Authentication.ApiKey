namespace Cirreum.Authentication.ApiKey;

using Cirreum.Authentication.Configuration;
/// <summary>
/// Options for API key validation behavior.
/// </summary>
public sealed class ApiKeyValidationOptions {

	/// <summary>
	/// Gets or sets the minimum allowed key length. Default is 32 characters.
	/// </summary>
	public int MinimumKeyLength { get; set; } = 32;

	/// <summary>
	/// Gets or sets the maximum allowed key length. Default is 512 characters.
	/// </summary>
	public int MaximumKeyLength { get; set; } = 512;

	/// <summary>
	/// Gets or sets whether expired keys should be allowed.
	/// Useful for debugging scenarios. Default is <see langword="false"/>.
	/// </summary>
	/// <remarks>
	/// When enabled, expired keys will still authenticate but the expiration
	/// status may be logged for diagnostic purposes.
	/// </remarks>
	public bool AllowExpiredKeys { get; set; } = false;

	/// <summary>
	/// Gets or sets the grace period to allow after key expiration.
	/// Default is <see cref="TimeSpan.Zero"/> (no grace period).
	/// </summary>
	public TimeSpan ExpirationGracePeriod { get; set; } = TimeSpan.Zero;

	/// <summary>
	/// Gets or sets whether to enforce that keys contain only valid characters.
	/// Default is <see langword="true"/>.
	/// </summary>
	public bool EnforceValidCharacters { get; set; } = true;

	/// <summary>
	/// Gets or sets the valid characters for API keys when <see cref="EnforceValidCharacters"/> is enabled.
	/// Default includes alphanumeric characters and common safe symbols.
	/// </summary>
	public string ValidCharacters { get; set; } = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/";

	// ---- Two-forms model (ADR-0020 §2/§3) -------------------------------------------------------
	// Form 1 = statically configured keys (appsettings / Key Vault), enforced at startup by the registrar.
	// Form 2 = dynamic managed keys (Cirreum-generated, hash-stored), strong by construction.

	/// <summary>
	/// The minimum estimated entropy (bits, per <see cref="ApiKeyEntropyEstimator"/>) a Form-1
	/// <em>statically configured</em> key must have. Enforced at startup by the registrar. Default 112
	/// (the NIST SP 800-63B §5.1.2 look-up-secret floor). Does NOT apply to Form-2 managed keys, which are
	/// Cirreum-generated and strong by construction; set <see cref="AllowWeakConfiguredKeys"/> to bypass.
	/// </summary>
	public int MinimumKeyEntropyBits { get; set; } = DefaultApiKeyGenerator.MinimumEntropyBits;

	/// <summary>
	/// When <see langword="true"/>, the startup strength check on Form-1 statically configured keys is
	/// skipped, allowing weak demo / prototype keys. <see langword="false"/> by default: a configured key
	/// below <see cref="MinimumKeyLength"/> or <see cref="MinimumKeyEntropyBits"/> fails fast at startup.
	/// Enable only for non-production use — appsettings secrets leak, and weak keys are guessable.
	/// </summary>
	public bool AllowWeakConfiguredKeys { get; set; }

	/// <summary>
	/// The stored-secret hash algorithm for the Form-2 dynamic (database-backed) model. Defaults to
	/// <see cref="ApiKeyHashAlgorithm.Sha256"/> — a fast salted hash, correct because managed keys are
	/// high-entropy by construction. <see cref="ApiKeyHashAlgorithm.Pbkdf2"/> is offered only for persisted
	/// hashes of imported / user-chosen low-entropy secrets. Static (Form-1) keys are compared in-memory
	/// and unaffected.
	/// </summary>
	public ApiKeyHashAlgorithm HashAlgorithm { get; set; } = ApiKeyHashAlgorithm.Sha256;

	/// <summary>
	/// The PBKDF2 work factor (iteration count) used when <see cref="HashAlgorithm"/> is
	/// <see cref="ApiKeyHashAlgorithm.Pbkdf2"/>. Verification uses the iteration count stored in each
	/// hash, so raising this affects only newly hashed keys.
	/// </summary>
	public int Pbkdf2Iterations { get; set; } = Pbkdf2ApiKeyHasher.DefaultIterations;

	/// <summary>
	/// When <see langword="true"/>, a key with no expiration is rejected on the validation path (both
	/// forms). <see langword="false"/> by default.
	/// </summary>
	public bool RequireExpiry { get; set; }

	/// <summary>
	/// The maximum permitted age of a key (NIST SP 800-57 cryptoperiod). Enforcement requires a
	/// key-creation timestamp on the stored key and the per-key override fields.
	/// </summary>
	public TimeSpan? MaxKeyAge { get; set; }
}
