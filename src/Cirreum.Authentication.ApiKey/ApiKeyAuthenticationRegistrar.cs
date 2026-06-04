namespace Cirreum.Authentication;

using System.Numerics;
using Cirreum.Authentication.ApiKey;
using Cirreum.Authentication.Configuration;
using Cirreum.AuthenticationProvider;
using Cirreum.AuthenticationProvider.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>
/// Registrar for the ApiKey authentication scheme. Inherits the
/// <see cref="HeaderAuthenticationProviderRegistrar{TSettings, TInstanceSettings}"/>
/// base cleanly and delegates ASP.NET scheme registration to the
/// shared static helpers in <see cref="ApiKeySchemeRegistration"/>. The same helpers
/// back the <c>AddApiKey(...)</c> composition verb, so the configured-instance path
/// (this registrar, invoked by the verb) and the declared-transport path converge on a
/// single scheme-registration code path with shared idempotency via
/// <see cref="ApiKeyProviderState"/>.
/// </summary>
/// <remarks>
/// <para>
/// Multi-scheme model: a provider with N
/// enabled instances each accepting exactly one transport produces up to
/// <c>1 + (count of distinct custom HeaderNames)</c> ASP.NET schemes. The shared
/// <see cref="ApiKeyClientRegistry"/> is the source of truth for which clients
/// accept which transports at runtime; per-scheme handlers query the registry only
/// for the transport they own.
/// </para>
/// <para>
/// Per-instance single-transport invariant: an ApiKey instance must declare
/// exactly one transport flag — split into separate instances if a client needs
/// to be reachable via multiple transports. Enforced in
/// <see cref="ValidateSettings"/>.
/// </para>
/// <para>
/// Composition is explicit: the app calls <c>auth.AddApiKey(...)</c> inside the umbrella
/// package's <c>AddAuthentication(...)</c> callback. The verb binds
/// this provider's configuration section and invokes <see cref="Register"/> directly;
/// ApiKey is not auto-registered by the umbrella.
/// </para>
/// </remarks>
public class ApiKeyAuthenticationRegistrar
	: HeaderAuthenticationProviderRegistrar<ApiKeyAuthenticationSettings, ApiKeyAuthenticationInstanceSettings> {

	/// <inheritdoc/>
	public override string ProviderName => "ApiKey";

	/// <inheritdoc/>
	public override void ValidateSettings(ApiKeyAuthenticationInstanceSettings settings) {

		if (string.IsNullOrWhiteSpace(settings.ClientId)) {
			throw new InvalidOperationException("ApiKey instance requires a ClientId.");
		}

		if (settings.AcceptedTransports == CredentialTransport.None) {
			throw new InvalidOperationException(
				$"ApiKey instance '{settings.ClientId}' requires exactly one accepted transport. " +
				$"Defaults to {nameof(CredentialTransport.BearerAuthorizationHeader)} when not set.");
		}

		// Single-transport invariant: split into separate instances if a client
		// needs to be reachable via multiple transports.
		var flagCount = BitOperations.PopCount((uint)settings.AcceptedTransports);
		if (flagCount != 1) {
			throw new InvalidOperationException(
				$"ApiKey instance '{settings.ClientId}' must specify exactly one transport " +
				$"(got '{settings.AcceptedTransports}', {flagCount} flags set). Split into " +
				$"separate instances if you need to accept multiple transports for the same client.");
		}

		if (settings.AcceptedTransports == CredentialTransport.CustomHeader
			&& string.IsNullOrWhiteSpace(settings.HeaderName)) {
			throw new InvalidOperationException(
				$"ApiKey instance '{settings.ClientId}' uses the CustomHeader transport but has no HeaderName configured.");
		}
	}

	/// <inheritdoc/>
	public override void Register(
		ApiKeyAuthenticationSettings providerSettings,
		IServiceCollection services,
		IConfiguration configuration,
		AuthenticationBuilder authBuilder) {

		if (providerSettings is null) {
			return;
		}

		// Stash provider-level state for the dynamic-resolver path. Done unconditionally —
		// even with zero Instances, the AddApiKey(...) verb may still need the prefix when
		// it registers the ApiKey:Bearer scheme for a declared transport.
		var state = ApiKeySchemeRegistration.GetOrAddState(services);
		state.BearerPrefix = providerSettings.BearerPrefix;

		if (providerSettings.Instances.Count == 0) {
			return;
		}

		// Supporting services — once per Register call, only when instances exist.
		// ConfigurationApiKeyClientResolver is registered as its concrete type rather
		// than pinned to IApiKeyClientResolver: the AddApiKey(...) verb owns the final
		// IApiKeyClientResolver wiring so it can compose the configuration resolver with
		// an optional dynamic resolver (CompositeApiKeyClientResolver) when both exist.
		services.TryAddSingleton<IApiKeyValidator, DefaultApiKeyValidator>();
		services.TryAddSingleton<ConfigurationApiKeyClientResolver>();

		// Per-instance phase: each enabled instance contributes a client to the
		// registry and (on first occurrence of its transport tuple) registers the
		// matching ASP.NET scheme + selector. See AddAuthenticationHandler.
		base.Register(providerSettings, services, configuration, authBuilder);
	}

	/// <inheritdoc/>
	protected override void AddAuthenticationHandler(
		string key,
		ApiKeyAuthenticationInstanceSettings settings,
		IServiceCollection services,
		IConfiguration configuration,
		AuthenticationBuilder authBuilder) {

		var registry = services.GetApiKeyClientRegistry();

		var apiKey = ResolveApiKey(key, configuration);

		ApiKeyValidation.ValidateApiKeyUniqueness(apiKey, key, settings.ClientId);

		var clientName = string.IsNullOrWhiteSpace(settings.ClientName)
			? settings.ClientId
			: settings.ClientName;

		registry.Register(new ApiKeyClientEntry(
			HeaderName: settings.HeaderName,
			Key: apiKey,
			ClientId: settings.ClientId,
			ClientName: clientName,
			Roles: settings.Roles,
			AcceptedTransports: settings.AcceptedTransports));

		// Single transport per instance (enforced by ValidateSettings) — switch
		// dispatches to the matching scheme-registration helper. Idempotency is
		// handled inside the helper via ApiKeyProviderState.TryClaimScheme: the
		// first instance wanting a given scheme registers it; subsequent
		// instances wanting the same scheme contribute their client to the
		// registry above and skip the helper's scheme registration.
		switch (settings.AcceptedTransports) {
			case CredentialTransport.BearerAuthorizationHeader:
				ApiKeySchemeRegistration.TryRegisterBearer(services, authBuilder);
				break;
			case CredentialTransport.CustomHeader:
				ApiKeySchemeRegistration.TryRegisterCustomHeader(services, authBuilder, settings.HeaderName);
				break;
			default:
				throw new InvalidOperationException(
					$"Unsupported ApiKey transport: {settings.AcceptedTransports}");
		}
	}

	private static string ResolveApiKey(
		string instanceKey,
		IConfiguration configuration) {

		var instanceSection = configuration.GetSection(
			$"Cirreum:Authentication:Providers:ApiKey:Instances:{instanceKey}");

		var apiKey = instanceSection.GetValue<string>("Key");
		if (string.IsNullOrWhiteSpace(apiKey)) {
			apiKey = configuration.GetConnectionString(instanceKey);
		}

		if (string.IsNullOrWhiteSpace(apiKey)) {
			throw new InvalidOperationException(
				$"Missing required Key for ApiKey instance '{instanceKey}'. " +
				$"Provide either Key in instance configuration or ConnectionStrings:{instanceKey}.");
		}

		return apiKey;
	}

}
