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
	/// <c>AddResolver(...)</c> path (a blind-scanned cheap resolver) is used with PBKDF2 hashing — which
	/// would expose a CPU-DoS through the fallback scan (use <c>AddDynamicStore(...)</c> instead).
	/// </summary>
	/// <param name="options">The composed ApiKey options (legacy resolver + named dynamic stores).</param>
	/// <param name="configuration">The application configuration.</param>
	internal static void Validate(ApiKeyOptions options, IConfiguration configuration) {
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(configuration);

		var validation = configuration.GetSection(ValidationSection).Get<ApiKeyValidationOptions>() ?? new();

		// §5: AddResolver(...) registers a blind-scanned (cheap fallback) dynamic resolver. It cannot
		// carry PBKDF2 hashing — a sprayer omitting X-Api-Source could otherwise force the expensive KDF
		// across the scan pool. Addressable-only managed stores (AddDynamicStore) may use any hasher.
		if (options.DynamicResolverType is not null && validation.HashAlgorithm == ApiKeyHashAlgorithm.Pbkdf2) {
			throw new InvalidOperationException(
				"AddResolver(...) registers a blind-scanned dynamic resolver (the cheap fallback path) and " +
				"cannot run PBKDF2 hashing — a sprayer omitting X-Api-Source could otherwise force PBKDF2 across " +
				"the scan pool, a CPU denial of service (ADR-0020 §5). Use AddDynamicStore<TResolver>(friendlyName) " +
				"to register an addressable-only managed store instead.");
		}
	}

}
