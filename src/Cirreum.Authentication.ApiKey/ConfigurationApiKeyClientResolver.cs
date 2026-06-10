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
	public Task<ApiKeyResolveResult> ResolveAsync(
		string providedKey,
		ApiKeyLookupContext context,
		CancellationToken cancellationToken = default) {

		var formatResult = this._validator.ValidateFormat(providedKey);
		if (!formatResult.IsValid) {
			if (this._logger.IsEnabled(LogLevel.Debug)) {
				this._logger.LogDebug(
					"API key format validation failed for transport {Transport}: {Reason}",
					context.Transport,
					formatResult.ErrorReason);
			}
			// A format reject is a pre-match MISS for this static source, not a definitive failure for the
			// whole chain: returning NotFound lets the dispatcher fall through to the dynamic sources, which
			// may legitimately issue keys in a different shape (N9). Failed is reserved for a matched key.
			return Task.FromResult(ApiKeyResolveResult.NotFound());
		}

		var entry = context.Transport.HasFlag(CredentialTransport.BearerAuthorizationHeader)
			? this._registry.ValidateBearerKey(providedKey)
			: this._registry.ValidateCustomHeaderKey(context.HeaderName, providedKey);

		if (entry is null) {
			if (this._logger.IsEnabled(LogLevel.Debug)) {
				this._logger.LogDebug(
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
			ExpiresAt = entry.ExpiresAt,
			CreatedAt = entry.CreatedAt,
			MaxKeyAge = entry.MaxKeyAge,
			Claims = null
		};

		if (this._logger.IsEnabled(LogLevel.Debug)) {
			this._logger.LogDebug(
				"API key resolved for client {ClientId} via {Transport}",
				client.ClientId,
				context.Transport);
		}

		return Task.FromResult(ApiKeyResolveResult.Success(client));
	}

}
