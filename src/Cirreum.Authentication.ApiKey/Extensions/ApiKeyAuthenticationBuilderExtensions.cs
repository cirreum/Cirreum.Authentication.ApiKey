namespace Cirreum.Authentication;

using Cirreum.Authentication.ApiKey;
using Cirreum.Authentication.Configuration;
using Cirreum.Authentication.Events;
using Cirreum.AuthenticationProvider;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// The <c>AddApiKey(...)</c> composition verb contributed by the ApiKey package.
/// Available inside the <c>configure</c> callback of <c>AddAuthentication(...)</c> on the
/// umbrella package — the single, unified entry point for the ApiKey
/// provider: it declares transports (the schemes that exist), binds any configured
/// instances from appsettings, and optionally wires dynamic API key sources.
/// </summary>
public static class ApiKeyAuthenticationBuilderExtensions {

	/// <summary>
	/// Composes the ApiKey authentication provider. Binds configured instances from
	/// <c>Cirreum:Authentication:Providers:ApiKey</c>, registers the declared transport
	/// schemes, and wires the credential-validation sources.
	/// </summary>
	/// <param name="builder">The Cirreum authentication builder.</param>
	/// <param name="configure">Optional options callback selecting transports
	/// (<see cref="ApiKeyOptions.AcceptTransports"/> / <see cref="ApiKeyOptions.AddCustomTransport"/>)
	/// and/or dynamic sources (<see cref="ApiKeyOptions.AddDefaultSource{T}"/> /
	/// <see cref="ApiKeyOptions.AddNamedSource{T}"/>). When omitted (or with no <c>AcceptTransports</c>
	/// call), all well-known transports register.</param>
	/// <returns>The builder for chaining.</returns>
	/// <remarks>
	/// <para>
	/// Validation-source resolution (in precedence order when no <c>X-Api-Source</c> is supplied):
	/// </para>
	/// <list type="bullet">
	///   <item>Statically configured instances → the configuration-backed resolver (tried first).</item>
	///   <item>A default dynamic source → the no-<c>X-Api-Source</c> fallback.</item>
	///   <item>Named dynamic sources → reached only via an explicit <c>X-Api-Source</c> reference.</item>
	///   <item>None → the dispatcher returns 401 for every request (an orphan transport); the
	///   boot-time auth-posture analyzer flags it.</item>
	/// </list>
	/// </remarks>
	public static IAuthenticationBuilder AddApiKey(
		this IAuthenticationBuilder builder,
		Action<ApiKeyOptions>? configure = null) {

		ArgumentNullException.ThrowIfNull(builder);

		var services = builder.Services;
		var state = ApiKeySchemeRegistration.GetOrAddState(services);
		if (!state.TryBeginComposition()) {
			throw new InvalidOperationException(
				"AddApiKey() has already been called for this host. Call it once during composition.");
		}

		var options = new ApiKeyOptions();
		configure?.Invoke(options);

		// 1. Bind the provider settings once (BearerPrefix + Instances + the Validation / Revocation
		//    sub-objects) and register the configured instances via the registrar.
		var providerSettings = BindConfiguredInstances(builder);

		// 1b. Register the validation options (from the bound settings) and the crypto primitives
		//     (key generator + self-describing hashers) used by validation (ADR-0020 P1/P2).
		RegisterValidationServices(services, providerSettings?.Validation);

		// 1c. Register the source catalog, the named dynamic sources (keyed by derived SourceRef for
		//     addressable dispatch), and the default dynamic source (ADR-0020 §4/§6).
		RegisterSources(services, options);

		// 1d. Register the revocation options (from the bound settings), the denylist, the CredentialRevoked
		//     handler, the boot hydrator + its fail-closed readiness gate, and the health check (ADR-0020 §8).
		RegisterRevocation(services, providerSettings?.Revocation);

		// 2. Register the declared transport schemes (idempotent against step 1's schemes).
		RegisterDeclaredTransportSchemes(options, services, builder.AuthBuilder);

		// 3. Wire the source dispatcher — the single IApiKeyClientResolver the handler calls.
		WireDispatcher(services);

		return builder;
	}

	private static ApiKeyAuthenticationSettings? BindConfiguredInstances(IAuthenticationBuilder builder) {

		var registrar = new ApiKeyAuthenticationRegistrar();
		var sectionKey = GetSectionPath(registrar.ProviderType, registrar.ProviderName);
		var section = builder.Configuration.GetSection(sectionKey);
		if (!section.Exists()) {
			return null;
		}

		var providerSettings = section.Get<ApiKeyAuthenticationSettings>()
			?? throw new InvalidOperationException(
				"Invalid configuration for ApiKey — section exists but cannot be bound to settings.");

		registrar.Register(
			providerSettings,
			builder.Services,
			builder.Configuration,
			builder.AuthBuilder);

		return providerSettings;
	}

	private static void RegisterValidationServices(
		IServiceCollection services,
		ApiKeyValidationOptions? validation) {

		// Provider-level validation options (the two-forms knobs: configured-key strength floor +
		// AllowWeakConfiguredKeys for Form 1; HashAlgorithm for Form 2), sourced from the bound provider
		// settings — defaults when no ApiKey section was configured.
		var effectiveValidation = validation ?? new ApiKeyValidationOptions();

		// Fail fast at boot if the PBKDF2 work factor is below the SP 800-132 / OWASP floor — a silent
		// sub-floor iteration count would defeat the one algorithm offered for imported low-entropy secrets
		// (N1). Enforced here (not only in the lazily-constructed hasher) so the misconfiguration surfaces
		// as a clean startup failure rather than a 500 on the first request.
		if (effectiveValidation.Pbkdf2Iterations < Pbkdf2ApiKeyHasher.MinIterations) {
			throw new InvalidOperationException(
				$"Cirreum:Authentication:Providers:ApiKey:Validation:Pbkdf2Iterations is " +
				$"{effectiveValidation.Pbkdf2Iterations}, below the {Pbkdf2ApiKeyHasher.MinIterations}-iteration " +
				$"minimum (NIST SP 800-132 / OWASP). Raise it to at least {Pbkdf2ApiKeyHasher.MinIterations} " +
				$"(the recommended default is {Pbkdf2ApiKeyHasher.DefaultIterations}).");
		}

		services.AddSingleton(Options.Create(effectiveValidation));

		// High-entropy key generator.
		services.TryAddSingleton<IApiKeyGenerator, DefaultApiKeyGenerator>();
		services.TryAddSingleton<IApiKeyValidator, DefaultApiKeyValidator>();

		// Self-describing hashers for the dynamic model; selected per the HashAlgorithm knob and
		// dispatched on verify by the encoded prefix.
		services.TryAddEnumerable(ServiceDescriptor.Singleton<IApiKeyHasher, Sha256ApiKeyHasher>());
		services.TryAddEnumerable(ServiceDescriptor.Singleton<IApiKeyHasher>(sp =>
			new Pbkdf2ApiKeyHasher(
				sp.GetRequiredService<IOptions<ApiKeyValidationOptions>>().Value.Pbkdf2Iterations)));

		// Boot-time advisory: makes a dialed-down validation posture (AllowExpiredKeys / AllowWeakConfiguredKeys
		// / no cryptoperiod) loud rather than silent (L1 / I-d). Observational only.
		services.AddHostedService<ApiKeyConfigurationAdvisory>();
	}

	private static void RegisterSources(IServiceCollection services, ApiKeyOptions options) {
		var catalog = GetOrAddCatalog(services);

		// Named, addressable sources: each is registered in the catalog (carrying its RequireClientId
		// policy). The app resolver type is registered SCOPED and reached per-request through a
		// scope-bridging resolver, so a scoped dependency (DbContext / repository / tenant context) is
		// never captured on the root container (N10). A caching decorator (singleton) sits in front when
		// configured, so only cache misses open a scope.
		foreach (var named in options.NamedSources) {
			var sourceRef = ApiKeySourceRef.Derive(named.FriendlyName);

			catalog.Register(new ApiKeySource {
				FriendlyName = named.FriendlyName,
				SourceRef = sourceRef,
				RequireClientId = named.RequireClientId,
			});

			var resolverType = named.ResolverType;
			var caching = named.Caching;
			services.TryAddScoped(resolverType);
			services.AddKeyedSingleton(sourceRef, (sp, _) =>
				WrapWithCaching(
					new ScopedApiKeyClientResolver(sp.GetRequiredService<IServiceScopeFactory>(), resolverType),
					caching, sp));
		}

		// The default (un-named) source — the no-X-Api-Source fallback, at most one. Same scoped + bridged
		// wiring as named sources.
		if (options.DefaultSource is { } def) {
			var defType = def.ResolverType;
			services.TryAddScoped(defType);
			services.AddSingleton(sp => new ApiKeyDefaultSource(
				WrapWithCaching(
					new ScopedApiKeyClientResolver(sp.GetRequiredService<IServiceScopeFactory>(), defType),
					def.Caching, sp),
				def.RequireClientId));
		}
	}

	private static void RegisterRevocation(IServiceCollection services, ApiKeyRevocationOptions? revocation) {
		// Revocation options sourced from the bound provider settings — defaults when no section configured.
		services.AddSingleton(Options.Create(revocation ?? new ApiKeyRevocationOptions()));

		services.TryAddSingleton<IApiKeyDenylist, ApiKeyDenylist>();
		services.TryAddSingleton<ApiKeyRevocationReadiness>();
		services.TryAddEnumerable(
			ServiceDescriptor.Singleton<IAuthenticationEventHandler<CredentialRevoked>, ApiKeyCredentialRevokedHandler>());
		services.AddHostedService<ApiKeyRevocationHydrator>();

		// Surface denylist authority so an orchestrator can pull an instance whose revocation state is
		// not trustworthy (fail-closed visibility for the hydration gate above).
		// We provide additional tags, but the "ready" tag effects the readiness of the application
		// if the denylist is not healthy.
		services.AddHealthChecks().AddCheck<ApiKeyRevocationHealthCheck>(
			ApiKeyRevocationHealthCheck.Name,
			tags: ["ready", "apikey", "authentication", "revocation"]);
	}

	private static ApiKeySourceCatalog GetOrAddCatalog(IServiceCollection services) {
		var descriptor = services.FirstOrDefault(d => d.ServiceType == typeof(ApiKeySourceCatalog));
		if (descriptor?.ImplementationInstance is ApiKeySourceCatalog existing) {
			return existing;
		}

		var catalog = new ApiKeySourceCatalog();
		services.AddSingleton(catalog);
		services.AddSingleton<IApiKeySourceCatalog>(catalog);
		return catalog;
	}

	private static void RegisterDeclaredTransportSchemes(
		ApiKeyOptions options,
		IServiceCollection services,
		Microsoft.AspNetCore.Authentication.AuthenticationBuilder authBuilder) {

		// AcceptedTransports is already resolved (all well-known by default, the restricted subset, or none);
		// custom headers are layered on top, additively. Bearer takes the Bearer path, every other
		// transport is a custom-header scheme. Registration is idempotent (TryClaimScheme), so overlaps
		// between a well-known transport and a same-named custom header collapse to one scheme.
		foreach (var transport in options.AcceptedTransports) {
			if (transport == ApiKeyTransport.Bearer) {
				ApiKeySchemeRegistration.TryRegisterBearer(services, authBuilder);
			} else {
				ApiKeySchemeRegistration.TryRegisterCustomHeader(services, authBuilder, transport.HeaderName());
			}
		}

		foreach (var headerName in options.CustomHeaders) {
			ApiKeySchemeRegistration.TryRegisterCustomHeader(services, authBuilder, headerName);
		}

	}

	private static void WireDispatcher(IServiceCollection services) {
		// The handler's IApiKeyClientResolver is the source dispatcher: it tries config first, falls back
		// to the default source, and routes X-Api-Source to keyed named sources — never blind-scanning
		// dynamic keys (ADR-0020 §5/§6). Config and the default source are optional (resolved as null
		// when not registered). The dispatcher does ROUTING only — the revocation-readiness gate, the
		// denylist consult, and expiry/cryptoperiod are enforced by ApiKeyAuthenticationHandler (the
		// non-replaceable chokepoint), so they hold even if an app re-registers IApiKeyClientResolver (N8).
		services.AddSingleton<IApiKeyClientResolver>(sp =>
			new ApiKeySourceDispatcher(
				sp.GetService<ConfigurationApiKeyClientResolver>(),
				sp.GetService<ApiKeyDefaultSource>(),
				sp.GetRequiredService<IApiKeySourceCatalog>(),
				sp,
				sp.GetRequiredService<ILogger<ApiKeySourceDispatcher>>()));
	}

	private static IApiKeyClientResolver WrapWithCaching(
		IApiKeyClientResolver inner,
		Action<ApiKeySourceCachingOptions>? caching,
		IServiceProvider sp) {

		if (caching is null) {
			return inner;
		}

		var cachingOptions = new ApiKeySourceCachingOptions();
		caching(cachingOptions);

		return new CachingApiKeyClientResolver(
			inner,
			Options.Create(cachingOptions),
			sp.GetRequiredService<ILogger<CachingApiKeyClientResolver>>());

	}

	private static string GetSectionPath(ProviderType providerType, string providerName) =>
		$"Cirreum:{providerType}:Providers:{providerName}";

}
