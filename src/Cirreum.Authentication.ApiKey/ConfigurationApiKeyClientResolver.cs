namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;
using Microsoft.Extensions.Logging;

/// <summary>
/// Default <see cref="IApiKeyClientResolver"/> backed by the configuration-populated
/// <see cref="ApiKeyClientRegistry"/>. Resolves keys statically loaded from
/// <c>appsettings.json</c> + Key Vault / connection strings at startup.
/// </summary>
public sealed class ConfigurationApiKeyClientResolver(
	ApiKeyClientRegistry registry,
	IApiKeyValidator validator,
	ILogger<ConfigurationApiKeyClientResolver> logger
) : IApiKeyClientResolver {

	private readonly ApiKeyClientRegistry _registry = registry ?? throw new ArgumentNullException(nameof(registry));
	private readonly IApiKeyValidator _validator = validator ?? throw new ArgumentNullException(nameof(validator));
	private readonly ILogger<ConfigurationApiKeyClientResolver> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

	/// <inheritdoc/>
	public IReadOnlySet<string> SupportedHeaders => _registry.RegisteredCustomHeaders;

	/// <inheritdoc/>
	public Task<ApiKeyResolveResult> ResolveAsync(
		string providedKey,
		ApiKeyLookupContext context,
		CancellationToken cancellationToken = default) {

		var formatResult = _validator.ValidateFormat(providedKey);
		if (!formatResult.IsValid) {
			if (_logger.IsEnabled(LogLevel.Debug)) {
				_logger.LogDebug(
					"API key format validation failed for transport {Transport}: {Reason}",
					context.Transport,
					formatResult.ErrorReason);
			}
			return Task.FromResult(ApiKeyResolveResult.Failed(formatResult.ErrorReason!));
		}

		var entry = context.Transport.HasFlag(CredentialTransport.BearerAuthorizationHeader)
			? _registry.ValidateBearerKey(providedKey)
			: _registry.ValidateCustomHeaderKey(context.HeaderName, providedKey);

		if (entry is null) {
			if (_logger.IsEnabled(LogLevel.Debug)) {
				_logger.LogDebug(
					"API key not found for transport {Transport} (header {HeaderName})",
					context.Transport,
					context.HeaderName);
			}
			return Task.FromResult(ApiKeyResolveResult.NotFound());
		}

		var client = new ApiKeyClient {
			ClientId = entry.ClientId,
			ClientName = entry.ClientName,
			Roles = entry.Roles,
			AcceptedTransports = entry.AcceptedTransports,
			ExpiresAt = null,
			Claims = null
		};

		if (_logger.IsEnabled(LogLevel.Debug)) {
			_logger.LogDebug(
				"API key resolved for client {ClientId} via {Transport}",
				client.ClientId,
				context.Transport);
		}

		return Task.FromResult(ApiKeyResolveResult.Success(client));
	}

}
