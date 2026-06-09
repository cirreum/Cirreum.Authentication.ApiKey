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
	/// Validates the ApiKey composition. Throws <see cref="InvalidOperationException"/> when the legacy
	/// <c>AddResolver(...)</c> path (a blind-scanned cheap resolver) is used with a hardened profile or
	/// PBKDF2 hashing — which would expose a CPU-DoS through the fallback scan (use
	/// <c>AddDynamicStore(...)</c> instead).
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
	}

}
