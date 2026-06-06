namespace Cirreum.Authentication.ApiKey;

using Microsoft.Extensions.Configuration;

/// <summary>
/// Composition-time fail-fast guards for the ApiKey provider (ADR-0020 §4). These run during
/// <c>AddApiKey(...)</c> and throw on an invalid posture, so a misconfiguration is surfaced at
/// startup rather than silently weakening authentication.
/// </summary>
internal static class ApiKeyCompositionValidator {

	private const string ValidationSection = "Cirreum:Authentication:Providers:ApiKey:Validation";
	private const string ProfileKey = ValidationSection + ":ConformanceProfile";

	/// <summary>
	/// Validates the ApiKey composition. Throws <see cref="InvalidOperationException"/> when:
	/// (1) a dynamic resolver is registered but no conformance profile is explicitly declared, or
	/// (2) the <see cref="ApiKeyConformanceProfile.SelfContained"/> profile is selected (its in-app
	/// distributed throttle is not yet available — use <see cref="ApiKeyConformanceProfile.EdgeThrottled"/>).
	/// </summary>
	/// <param name="options">The composed ApiKey options (carries the dynamic resolver type, if any).</param>
	/// <param name="configuration">The application configuration.</param>
	internal static void Validate(ApiKeyOptions options, IConfiguration configuration) {
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(configuration);

		var validation = configuration.GetSection(ValidationSection).Get<ApiKeyValidationOptions>() ?? new();

		// §4: a dynamic (database-backed) store MUST resolve to an explicit profile. Static config
		// instances inherit Baseline silently, but a self-service DB store must never default to the
		// weakest posture — so require an explicit declaration when a dynamic resolver is present.
		var profileDeclared = !string.IsNullOrWhiteSpace(configuration[ProfileKey]);
		if (options.DynamicResolverType is not null && !profileDeclared) {
			throw new InvalidOperationException(
				"A dynamic ApiKey resolver is registered but no conformance profile is declared. Set " +
				$"'{ProfileKey}' to 'Baseline', 'EdgeThrottled', or 'SelfContained' — a database-backed " +
				"store must never silently run the weakest posture (ADR-0020 §4).");
		}

		// The SelfContained profile's defining control — in-app distributed throttling — is not yet
		// available (pending the ICacheService atomic-counter capability). Fail fast rather than give
		// a false sense of throttling; EdgeThrottled (platform-edge throttling) is the conformant
		// option until the in-app throttle ships.
		if (validation.ConformanceProfile == ApiKeyConformanceProfile.SelfContained) {
			throw new InvalidOperationException(
				"The 'SelfContained' ApiKey conformance profile requires in-app distributed throttling, " +
				"which is not yet available. Use 'EdgeThrottled' (platform-edge throttling) until the " +
				"in-app throttle ships (ADR-0020 §3/§8).");
		}
	}

}
