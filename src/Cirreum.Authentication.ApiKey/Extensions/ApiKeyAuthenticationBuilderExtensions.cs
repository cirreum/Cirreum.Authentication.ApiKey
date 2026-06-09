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

	private static readonly string[] WellKnownTransports = [
		ApiKeyTransports.Bearer,
		ApiKeyTransports.XApiKey,
		ApiKeyTransports.OcpApimSubscriptionKey,
		ApiKeyTransports.XAuthToken,
	];

	/// <summary>
	/// Composes the ApiKey authentication provider. Binds configured instances from
	/// <c>Cirreum:Authentication:Providers:ApiKey</c>, registers the declared transport
	/// schemes, and wires the credential-validation sources.
	/// </summary>
	/// <param name="builder">The Cirreum authentication builder.</param>
	/// <param name="configure">Optional options callback selecting transports
	/// (<see cref="ApiKeyOptions.AddTransport"/> / <see cref="ApiKeyOptions.AddCustomHeaderTransport"/>)
	/// and/or dynamic sources (<see cref="ApiKeyOptions.AddDefaultSource{T}"/> /
	/// <see cref="ApiKeyOptions.AddNamedSource{T}"/>). When omitted (or with no transport declared), all
	/// well-known transports register.</param>
	/// <returns>The builder for chaining.</returns>
	/// <remarks>
	/// <para>
	/// Validation-source resolution (in precedence order when no <c>X-Api-Source</c> is supplied):
	/// </para>
	/// <list type="bullet">
	///   <item>Statically configured instances → the configuration-backed resolver (tried first).</item>
	///   <item>A default dynamic source → the no-<c>X-Api-Source</c> fallback.</item>
	///   <item>Named dynamic sources → reached only via an explicit <c>X-Api-Source</c> reference.</item>
	///   <item>None → a no-op resolver so orphaned schemes return 401 cleanly; the
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

		// 1b. Bind the validation knobs (the two-forms strength + hashing options) and register the crypto
		//     primitives (key generator + self-describing hashers) used by validation (ADR-0020 P1/P2).
		RegisterValidationServices(services, builder.Configuration);

		// 1c. Register the source catalog, the named dynamic sources (keyed by derived SourceRef for
		//     addressable dispatch), and the default dynamic source (ADR-0020 §4/§6).
		RegisterSources(services, options);

		// 1d. Register the revocation denylist, the CredentialRevoked auth-event handler, the boot-time
		//     hydrator + its fail-closed readiness gate, and the revocation health check (ADR-0020 §8).
		RegisterRevocation(services, builder.Configuration);

		// 2. Register the declared transport schemes (idempotent against step 1's schemes).
		RegisterDeclaredTransports(options, services, builder.AuthBuilder);

		// 3. Wire the source dispatcher — the single IApiKeyClientResolver the handler calls.
		WireDispatcher(services);

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

		// Provider-level validation options (the two-forms knobs: configured-key strength floor +
		// AllowWeakConfiguredKeys for Form 1; HashAlgorithm for Form 2). Defaults live on the options type.
		services.Configure<ApiKeyValidationOptions>(
			configuration.GetSection("Cirreum:Authentication:Providers:ApiKey:Validation"));

		// High-entropy key generator.
		services.TryAddSingleton<IApiKeyGenerator, DefaultApiKeyGenerator>();
		services.TryAddSingleton<IApiKeyValidator, DefaultApiKeyValidator>();

		// Self-describing hashers for the dynamic model; selected per the HashAlgorithm knob and
		// dispatched on verify by the encoded prefix.
		services.TryAddEnumerable(ServiceDescriptor.Singleton<IApiKeyHasher, Sha256ApiKeyHasher>());
		services.TryAddEnumerable(ServiceDescriptor.Singleton<IApiKeyHasher>(sp =>
			new Pbkdf2ApiKeyHasher(
				sp.GetRequiredService<IOptions<ApiKeyValidationOptions>>().Value.Pbkdf2Iterations)));
	}

	private static void RegisterSources(IServiceCollection services, ApiKeyOptions options) {
		var catalog = GetOrAddCatalog(services);

		// Named, addressable sources: each is registered in the catalog (carrying its RequireClientId
		// policy) and its resolver is registered in DI keyed by the derived SourceRef.
		foreach (var named in options.NamedSources) {
			var sourceRef = ApiKeySourceRef.Derive(named.FriendlyName);

			catalog.Register(new ApiKeySource {
				FriendlyName = named.FriendlyName,
				SourceRef = sourceRef,
				RequireClientId = named.RequireClientId,
			});

			var resolverType = named.ResolverType;
			var caching = named.Caching;
			services.AddKeyedSingleton<IApiKeyClientResolver>(sourceRef, (sp, _) =>
				WrapWithCaching((IApiKeyClientResolver)ActivatorUtilities.CreateInstance(sp, resolverType), caching, sp));
		}

		// The default (un-named) source — the no-X-Api-Source fallback, at most one.
		if (options.DefaultSource is { } def) {
			services.AddSingleton(sp => new ApiKeyDefaultSource(
				WrapWithCaching((IApiKeyClientResolver)ActivatorUtilities.CreateInstance(sp, def.ResolverType), def.Caching, sp),
				def.RequireClientId));
		}
	}

	private static void RegisterRevocation(IServiceCollection services, IConfiguration configuration) {
		services.Configure<ApiKeyRevocationOptions>(
			configuration.GetSection("Cirreum:Authentication:Providers:ApiKey:Revocation"));

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

	private static void WireDispatcher(IServiceCollection services) {
		// The handler's IApiKeyClientResolver is the source dispatcher: it tries config first, falls back
		// to the default source, and routes X-Api-Source to keyed named sources — never blind-scanning
		// dynamic keys (ADR-0020 §5/§6). Config and the default source are optional (resolved as null
		// when not registered).
		services.AddSingleton<IApiKeyClientResolver>(sp =>
			new ApiKeySourceDispatcher(
				sp.GetService<ConfigurationApiKeyClientResolver>(),
				sp.GetService<ApiKeyDefaultSource>(),
				sp.GetRequiredService<IApiKeySourceCatalog>(),
				sp.GetRequiredService<IApiKeyDenylist>(),
				sp.GetRequiredService<ApiKeyRevocationReadiness>(),
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

}
