namespace Cirreum.Authentication;

using Cirreum.Authentication.ApiKey;
using Cirreum.Authentication.Configuration;
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
/// instances from appsettings, and optionally wires a dynamic resolver.
/// </summary>
public static class ApiKeyAuthenticationBuilderExtensions {

	private static readonly string[] WellKnownTransports = [
		ApiKeyTransports.Bearer,
		ApiKeyTransports.XApiKey,
		ApiKeyTransports.OcpApimSubscriptionKey,
		ApiKeyTransports.XAuthToken,
	];

	/// <summary>
	/// Composes the ApiKey authentication provider. Binds configured instances from
	/// <c>Cirreum:Authentication:Providers:ApiKey</c>, registers the declared transport
	/// schemes, and wires the credential-validation source.
	/// </summary>
	/// <param name="builder">The Cirreum authentication builder.</param>
	/// <param name="configure">Optional options callback selecting transports
	/// (<see cref="ApiKeyOptions.AddTransport"/> / <see cref="ApiKeyOptions.AddCustomHeaderTransport"/>)
	/// and/or a dynamic resolver (<see cref="ApiKeyOptions.AddResolver{T}"/>). When
	/// omitted (or with no transport declared), all well-known transports register.</param>
	/// <returns>The builder for chaining.</returns>
	/// <remarks>
	/// <para>
	/// Validation-source resolution:
	/// </para>
	/// <list type="bullet">
	///   <item>Configured instances only → the configuration-backed resolver.</item>
	///   <item>Dynamic resolver only → that resolver (optionally cached).</item>
	///   <item>Both → the configuration resolver composed ahead of the dynamic resolver
	///   (<see cref="CompositeApiKeyClientResolver"/>): configured keys are tried first,
	///   then the dynamic store.</item>
	///   <item>Neither → a no-op resolver so orphaned schemes return 401 cleanly; the
	///   boot-time auth-posture analyzer flags the orphan transports.</item>
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

		// 1. Bind + register configured instances (appsettings). The registrar stashes
		//    BearerPrefix, registers ConfigurationApiKeyClientResolver as a concrete type,
		//    populates the client registry, and registers the schemes the instances use.
		var providerSettings = BindConfiguredInstances(builder);

		// 1b. Bind the conformance profile + validation knobs and register the crypto primitives
		//     (key generator + self-describing hashers) used by validation (ADR-0020 P1/P2).
		RegisterValidationServices(services, builder.Configuration);

		// 1c. Register the source catalog and any named dynamic stores (ADR-0020 §4/§6). Each store's
		//     resolver is registered in DI keyed by its derived SourceRef for addressable dispatch.
		RegisterSourceCatalog(services, options);

		// 2. Register the declared transport schemes (idempotent against step 1's schemes).
		RegisterDeclaredTransports(options, services, builder.AuthBuilder);

		// 3. Wire the active IApiKeyClientResolver from the available validation sources.
		WireResolver(options, services, hasInstances: providerSettings is { Instances.Count: > 0 });

		// 4. Composition fail-fast guards (ADR-0020 §4): a dynamic store must declare an explicit
		//    profile; SelfContained is rejected until its in-app throttle ships.
		ApiKeyCompositionValidator.Validate(options, builder.Configuration);

		return builder;
	}

	private static ApiKeyAuthenticationSettings? BindConfiguredInstances(IAuthenticationBuilder builder) {

		var section = builder.Configuration.GetSection("Cirreum:Authentication:Providers:ApiKey");
		if (!section.Exists()) {
			return null;
		}

		var providerSettings = section.Get<ApiKeyAuthenticationSettings>()
			?? throw new InvalidOperationException(
				"Invalid configuration for ApiKey — section exists but cannot be bound to settings.");

		new ApiKeyAuthenticationRegistrar().Register(
			providerSettings,
			builder.Services,
			builder.Configuration,
			builder.AuthBuilder);

		return providerSettings;
	}

	private static void RegisterValidationServices(
		IServiceCollection services,
		IConfiguration configuration) {

		// Provider-level validation options (ConformanceProfile + knobs). Framework defaults live on
		// the options type (= Baseline); per-store overrides layer on in a later phase.
		services.Configure<ApiKeyValidationOptions>(
			configuration.GetSection("Cirreum:Authentication:Providers:ApiKey:Validation"));

		// High-entropy key generator.
		services.TryAddSingleton<IApiKeyGenerator, DefaultApiKeyGenerator>();

		// Self-describing hashers for the dynamic model; selected per the HashAlgorithm knob and
		// dispatched on verify by the encoded prefix.
		services.TryAddEnumerable(ServiceDescriptor.Singleton<IApiKeyHasher, Sha256ApiKeyHasher>());
		services.TryAddEnumerable(ServiceDescriptor.Singleton<IApiKeyHasher>(sp =>
			new Pbkdf2ApiKeyHasher(
				sp.GetRequiredService<IOptions<ApiKeyValidationOptions>>().Value.Pbkdf2Iterations)));
	}

	private static void RegisterSourceCatalog(IServiceCollection services, ApiKeyOptions options) {
		var catalog = GetOrAddCatalog(services);

		foreach (var store in options.DynamicStores) {
			var sourceRef = ApiKeySourceRef.Derive(store.FriendlyName);

			catalog.Register(new ApiKeySource {
				FriendlyName = store.FriendlyName,
				SourceRef = sourceRef,
				Profile = store.Profile,
				Kind = ApiKeySourceKind.Dynamic,
			});

			// The store's resolver is addressable by its SourceRef (dispatch wired in P4b).
			services.AddKeyedSingleton(typeof(IApiKeyClientResolver), sourceRef, store.ResolverType);
		}
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

	private static void RegisterDeclaredTransports(
		ApiKeyOptions options,
		IServiceCollection services,
		Microsoft.AspNetCore.Authentication.AuthenticationBuilder authBuilder) {

		var transports = options.HasExplicitTransports
			? options.Transports
			: WellKnownTransports;

		foreach (var transport in transports) {
			if (string.Equals(transport, ApiKeyTransports.Bearer, StringComparison.OrdinalIgnoreCase)) {
				ApiKeySchemeRegistration.TryRegisterBearer(services, authBuilder);
			} else {
				ApiKeySchemeRegistration.TryRegisterCustomHeader(services, authBuilder, transport);
			}
		}

		foreach (var headerName in options.CustomHeaders) {
			ApiKeySchemeRegistration.TryRegisterCustomHeader(services, authBuilder, headerName);
		}
	}

	private static void WireResolver(
		ApiKeyOptions options,
		IServiceCollection services,
		bool hasInstances) {

		services.TryAddSingleton<IApiKeyValidator, DefaultApiKeyValidator>();

		var resolverType = options.DynamicResolverType;

		if (resolverType is null) {
			// Configuration-only, or no source at all.
			if (hasInstances) {
				services.TryAddSingleton<IApiKeyClientResolver>(sp =>
					sp.GetRequiredService<ConfigurationApiKeyClientResolver>());
			} else {
				services.TryAddSingleton<IApiKeyClientResolver, NullApiKeyClientResolver>();
			}
			return;
		}

		// Dynamic resolver present — register it as its concrete type.
		services.TryAddSingleton(resolverType);
		if (options.CachingConfigure is not null) {
			services.Configure(options.CachingConfigure);
		}

		services.Replace(ServiceDescriptor.Singleton<IApiKeyClientResolver>(sp => {
			var dynamicResolver = WrapWithCaching(
				(IApiKeyClientResolver)sp.GetRequiredService(resolverType),
				options.CachingConfigure is not null,
				sp);

			if (!hasInstances) {
				return dynamicResolver;
			}

			return new CompositeApiKeyClientResolver(
				[sp.GetRequiredService<ConfigurationApiKeyClientResolver>(), dynamicResolver],
				sp.GetRequiredService<ILogger<CompositeApiKeyClientResolver>>());
		}));
	}

	private static IApiKeyClientResolver WrapWithCaching(
		IApiKeyClientResolver inner,
		bool caching,
		IServiceProvider sp) =>
		caching
			? new CachingApiKeyClientResolver(
				inner,
				sp.GetRequiredService<IOptions<ApiKeyCachingOptions>>(),
				sp.GetRequiredService<ILogger<CachingApiKeyClientResolver>>())
			: inner;

}
