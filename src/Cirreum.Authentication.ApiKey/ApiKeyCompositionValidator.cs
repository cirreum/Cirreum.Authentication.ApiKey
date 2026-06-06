namespace Cirreum.Authentication.ApiKey;

using Microsoft.Extensions.Configuration;

/// <summary>
/// Composition-time fail-fast guards for the ApiKey provider (ADR-0020 §4/§5). These run during
/// <c>AddApiKey(...)</c> and throw on an invalid posture, so a misconfiguration is surfaced at
/// startup rather than silently weakening authentication or exposing a CPU denial of service.
/// </summary>
internal static class ApiKeyCompositionValidator {

	private const string ValidationSection = "Cirreum:Authentication:Providers:ApiKey:Validation";

	/// <summary>
	/// Validates the ApiKey composition. Throws <see cref="InvalidOperationException"/> when:
	/// (1) the legacy <c>AddResolver(...)</c> path (a blind-scanned cheap resolver) is used with a
	/// hardened profile or PBKDF2 hashing — which would expose a CPU-DoS through the fallback scan
	/// (use <c>AddDynamicStore(...)</c> instead); or (2) the <see cref="ApiKeyConformanceProfile.SelfContained"/>
	/// profile is requested anywhere (its in-app distributed throttle is not yet available).
	/// </summary>
	/// <param name="options">The composed ApiKey options (legacy resolver + named dynamic stores).</param>
	/// <param name="configuration">The application configuration.</param>
	internal static void Validate(ApiKeyOptions options, IConfiguration configuration) {
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(configuration);

		var validation = configuration.GetSection(ValidationSection).Get<ApiKeyValidationOptions>() ?? new();

		// §5: AddResolver(...) registers a blind-scanned (cheap fallback) dynamic resolver. It cannot
		// carry a hardened profile or PBKDF2 hashing — a sprayer omitting X-Api-Source could otherwise
		// force the expensive operation across the scan pool. Hardened/addressable stores use AddDynamicStore.
		if (options.DynamicResolverType is not null &&
			(validation.ConformanceProfile != ApiKeyConformanceProfile.Baseline ||
			 validation.HashAlgorithm == ApiKeyHashAlgorithm.Pbkdf2)) {
			throw new InvalidOperationException(
				"AddResolver(...) registers a blind-scanned dynamic resolver (the cheap fallback path) and " +
				"cannot run a hardened conformance profile or PBKDF2 hashing — that would expose a CPU denial " +
				"of service through the fallback scan (ADR-0020 §5). Use AddDynamicStore<TResolver>(friendlyName, " +
				"profile) to register an addressable-only store with a hardened profile instead.");
		}

		// SelfContained's defining control — in-app distributed throttling — is not yet available
		// (pending the ICacheService atomic-counter capability). Fail fast wherever it is requested
		// (provider-level or any named store) rather than imply throttling that isn't there.
		var selfContainedRequested =
			validation.ConformanceProfile == ApiKeyConformanceProfile.SelfContained ||
			options.DynamicStores.Any(s => s.Profile == ApiKeyConformanceProfile.SelfContained);

		if (selfContainedRequested) {
			throw new InvalidOperationException(
				"The 'SelfContained' ApiKey conformance profile requires in-app distributed throttling, which " +
				"is not yet available. Use 'EdgeThrottled' (platform-edge throttling) until the in-app throttle " +
				"ships (ADR-0020 §3/§8).");
		}
	}

}
