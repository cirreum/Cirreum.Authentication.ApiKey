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
	/// edge (gateway / ingress / APIM / Front Door / App Gateway WAF). Imposes the entropy floor and a
	/// bounded cryptoperiod; the §5.2.2 throttling control is owned outside the app.
	/// </summary>
	/// <remarks>
	/// The fronting edge is the operator's responsibility and is <em>not</em> verifiable by the framework:
	/// a plain-ACA deployment with no edge WAF has no failed-attempt throttle, so this profile's §5.2.2
	/// conformance is then an unverified external claim. Acceptable in practice for a ≥112-bit look-up secret
	/// (online guessing is infeasible; SignedRequest's replay guard is the in-app anti-abuse control) — but a
	/// deployment that needs the §5.2.2 <em>attestation</em> must provision an edge; there is no in-app
	/// fallback now that <c>SelfContained</c> is dropped. (ADR-0020, 2026-06-08.)
	/// </remarks>
	EdgeThrottled = 1

}
