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

	// ---- Conformance profile + knobs (ADR-0020 §2/§3) -------------------------------------------

	/// <summary>
	/// The conformance profile bundle. Defaults to <see cref="ApiKeyConformanceProfile.Baseline"/>,
	/// which preserves the framework's historical behavior. The non-Baseline profiles raise the
	/// entropy floor and require a cryptoperiod; the individual knobs below may only tighten them.
	/// </summary>
	public ApiKeyConformanceProfile ConformanceProfile { get; set; } = ApiKeyConformanceProfile.Baseline;

	/// <summary>
	/// The minimum estimated entropy (in bits) a presented key must have, per
	/// <see cref="ApiKeyEntropyEstimator"/>. <c>0</c> disables the check (the Baseline default). The
	/// effective floor is the larger of this value and the profile's floor — see
	/// <see cref="EffectiveMinimumEntropyBits"/>.
	/// </summary>
	public int MinimumKeyEntropyBits { get; set; }

	/// <summary>
	/// The stored-secret hash algorithm for the dynamic (database-backed) model. Defaults to
	/// <see cref="ApiKeyHashAlgorithm.Sha256"/>. Static Key-Vault keys are unaffected (compared in-memory).
	/// </summary>
	public ApiKeyHashAlgorithm HashAlgorithm { get; set; } = ApiKeyHashAlgorithm.Sha256;

	/// <summary>
	/// The PBKDF2 work factor (iteration count) used when <see cref="HashAlgorithm"/> is
	/// <see cref="ApiKeyHashAlgorithm.Pbkdf2"/>. Verification uses the iteration count stored in each
	/// hash, so raising this affects only newly hashed keys.
	/// </summary>
	public int Pbkdf2Iterations { get; set; } = Pbkdf2ApiKeyHasher.DefaultIterations;

	/// <summary>
	/// When <see langword="true"/>, a key with no expiration is rejected. <see langword="false"/> by
	/// default (Baseline); the non-Baseline profiles force this on — see <see cref="EffectiveRequireExpiry"/>.
	/// </summary>
	public bool RequireExpiry { get; set; }

	/// <summary>
	/// The maximum permitted age of a key (NIST SP 800-57 cryptoperiod). Enforcement requires a
	/// key-creation timestamp on the stored key and is wired with the per-key override fields; the
	/// knob is declared here so the profile/appsettings surface is complete.
	/// </summary>
	public TimeSpan? MaxKeyAge { get; set; }

	/// <summary>
	/// The effective minimum entropy floor after applying the profile: the larger of
	/// <see cref="MinimumKeyEntropyBits"/> and the profile floor (0 for Baseline, the
	/// NIST SP 800-63B §5.1.2 look-up-secret floor for the hardened profiles). Tighten-only.
	/// </summary>
	public int EffectiveMinimumEntropyBits =>
		this.ConformanceProfile == ApiKeyConformanceProfile.Baseline
			? this.MinimumKeyEntropyBits
			: Math.Max(DefaultApiKeyGenerator.MinimumEntropyBits, this.MinimumKeyEntropyBits);

	/// <summary>
	/// Whether expiry is effectively required after applying the profile: <see langword="true"/> when
	/// the profile is non-Baseline or <see cref="RequireExpiry"/> is set. Tighten-only.
	/// </summary>
	public bool EffectiveRequireExpiry =>
		this.ConformanceProfile != ApiKeyConformanceProfile.Baseline || this.RequireExpiry;
}
