namespace Cirreum.Authentication.ApiKey;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods on <see cref="IServiceCollection"/> for the ApiKey scheme.
/// </summary>
public static class ServiceCollectionExtensions {

	/// <summary>
	/// Gets the singleton <see cref="ApiKeyClientRegistry"/> — creating and adding
	/// it on first call. The registrar uses this to register client entries; the
	/// handler uses it (transitively through <see cref="IApiKeyClientResolver"/>)
	/// to validate inbound credentials.
	/// </summary>
	public static ApiKeyClientRegistry GetApiKeyClientRegistry(this IServiceCollection services) {
		var descriptor = services.FirstOrDefault(d =>
			d.ServiceType == typeof(ApiKeyClientRegistry));

		if (descriptor?.ImplementationInstance is ApiKeyClientRegistry registry) {
			return registry;
		}

		registry = new ApiKeyClientRegistry();
		services.AddSingleton(registry);
		return registry;
	}

}
