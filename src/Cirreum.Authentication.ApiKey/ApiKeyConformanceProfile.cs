namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// A vetted bundle of API key conformance knobs (ADR-0020 §2). The profile is the primary
/// surface; individual knobs on <see cref="ApiKeyValidationOptions"/> fine-tune and may only
/// <em>tighten</em> the chosen profile's floor. Profiles are named for <em>what they do</em> — the
/// standards mapping is carried by the conformance documentation, not the name.
/// </summary>
public enum ApiKeyConformanceProfile {

	/// <summary>
	/// No imposed entropy floor, throttling, or cryptoperiod. Preserves the framework's historical
	/// behavior; the default for static (config) key sets.
	/// </summary>
	Baseline = 0,

	/// <summary>
	/// NIST SP 800-63B-conformant with failed-attempt throttling delegated to an attested platform
	/// edge (gateway / ingress / APIM). Imposes the entropy floor and a bounded cryptoperiod; the
	/// throttling control is owned outside the app.
	/// </summary>
	EdgeThrottled = 1,

	/// <summary>
	/// NIST SP 800-63B-conformant with the entire control set owned in-app (no external attestation
	/// dependency). Imposes the entropy floor and a bounded cryptoperiod; failed-attempt throttling
	/// is owned in-process via the distributed cache tier.
	/// </summary>
	SelfContained = 2

}
