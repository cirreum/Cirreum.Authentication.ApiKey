namespace Cirreum.Authentication.ApiKey;

using Microsoft.Extensions.Logging;

/// <summary>
/// Base class for implementing database-backed or external API key resolvers.
/// Handles common concerns like validation, hash comparison, and expiration checking.
/// </summary>
/// <remarks>
/// <para>
/// Inherit from this class to create a custom resolver. You only need to implement:
/// <list type="bullet">
///   <item><see cref="SupportedHeaders"/> - which headers your resolver handles</item>
///   <item><see cref="LookupKeysAsync"/> - your database/external lookup logic</item>
/// </list>
/// </para>
/// <para>
/// The base class handles format validation, secure hash comparison, expiration
/// checking, and result construction.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// public class MyDatabaseResolver : DynamicApiKeyClientResolver {
///     private readonly IApiKeyRepository _repository;
///
///     public MyDatabaseResolver(
///         IApiKeyRepository repository,
///         IApiKeyValidator validator,
///         ILogger&lt;MyDatabaseResolver&gt; logger)
///         : base(validator, logger) {
///         _repository = repository;
///     }
///
///     public override IReadOnlySet&lt;string&gt; SupportedHeaders =&gt;
///         new HashSet&lt;string&gt; { "X-Api-Key" };
///
///     protected override Task&lt;IEnumerable&lt;StoredApiKey&gt;&gt; LookupKeysAsync(
///         ApiKeyLookupContext context,
///         CancellationToken cancellationToken) {
///         // Use X-Client-Id header for efficient filtering
///         var clientId = context.GetHeader("X-Client-Id");
///         if (!string.IsNullOrEmpty(clientId)) {
///             return _repository.FindByClientIdAsync(clientId, cancellationToken);
///         }
///         return _repository.FindByHeaderAsync(context.HeaderName, cancellationToken);
///     }
/// }
/// </code>
/// </example>
/// <remarks>
/// Initializes a new instance of the <see cref="DynamicApiKeyClientResolver"/> class.
/// </remarks>
/// <param name="validator">The API key validator for format and hash validation.</param>
/// <param name="logger">The logger instance.</param>
public abstract class DynamicApiKeyClientResolver(
	IApiKeyValidator validator,
	ILogger logger
) : IApiKeyClientResolver {

	private readonly IApiKeyValidator _validator = validator ?? throw new ArgumentNullException(nameof(validator));
	private readonly ILogger _logger = logger ?? throw new ArgumentNullException(nameof(logger));

	/// <inheritdoc/>
	public abstract IReadOnlySet<string> SupportedHeaders { get; }

	/// <summary>
	/// Looks up stored API keys from the database or external source.
	/// </summary>
	/// <param name="context">
	/// Context containing the header name and additional request headers.
	/// Use <see cref="ApiKeyLookupContext.GetHeader"/> to access headers like
	/// <c>X-Client-Id</c> for efficient filtering.
	/// </param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>
	/// The stored keys matching the context, or an empty collection if none exist.
	/// </returns>
	/// <remarks>
	/// <para>
	/// Use the context to optimize your database queries. For example:
	/// </para>
	/// <code>
	/// var clientId = context.GetHeader("X-Client-Id");
	/// if (!string.IsNullOrEmpty(clientId)) {
	///     // Efficient: query by client ID returns at most one key
	///     return _repository.FindByClientIdAsync(clientId, cancellationToken);
	/// }
	/// // Fallback: return all keys for the header
	/// return _repository.FindByHeaderAsync(context.HeaderName, cancellationToken);
	/// </code>
	/// </remarks>
	protected abstract Task<IEnumerable<StoredApiKey>> LookupKeysAsync(
		ApiKeyLookupContext context,
		CancellationToken cancellationToken);

	/// <inheritdoc/>
	public async Task<ApiKeyResolveResult> ResolveAsync(
		string providedKey,
		ApiKeyLookupContext context,
		CancellationToken cancellationToken = default) {

		var headerName = context.HeaderName;

		// Per-store conformance profile (when routed via X-Api-Source); null falls back to provider-global.
		var profile = context.Source?.Profile;

		// 1. Validate format (entropy floor enforced per the store's profile)
		var formatResult = this._validator.ValidateFormat(providedKey, profile);
		if (!formatResult.IsValid) {
			if (this._logger.IsEnabled(LogLevel.Debug)) {
				this._logger.LogDebug(
					"API key format validation failed for header {HeaderName}: {Reason}",
					headerName,
					formatResult.ErrorReason);
			}
			return ApiKeyResolveResult.Failed(formatResult.ErrorReason!);
		}

		// 2. Lookup stored keys (implementations can use context for filtering)
		IEnumerable<StoredApiKey> storedKeys;
		try {
			storedKeys = await this.LookupKeysAsync(context, cancellationToken);
		} catch (Exception ex) {
			if (this._logger.IsEnabled(LogLevel.Error)) {
				this._logger.LogError(ex,
				"Error looking up API keys for header {HeaderName}",
				headerName);
			}
			return ApiKeyResolveResult.Failed("Key lookup failed");
		}

		// 3. Find matching key using secure hash comparison. VerifyKey dispatches self-describing
		//    (PHC) hashes to the matching hasher and falls back to the legacy salted-SHA-256 path.
		foreach (var storedKey in storedKeys) {
			if (!this._validator.VerifyKey(providedKey, storedKey.KeyHash, storedKey.Salt)) {
				continue;
			}

			// 4. Check expiration (RequireExpiry enforced per the store's profile)
			if (this._validator.IsExpired(storedKey.ExpiresAt, null, profile)) {
				if (this._logger.IsEnabled(LogLevel.Debug)) {
					this._logger.LogDebug(
						"API key expired for client {ClientId} on header {HeaderName}",
						storedKey.ClientId,
						headerName);
				}
				return ApiKeyResolveResult.Expired();
			}

			// 5. Success - build client
			var client = storedKey.ToApiKeyClient();

			if (this._logger.IsEnabled(LogLevel.Debug)) {
				this._logger.LogDebug(
					"API key resolved for client {ClientId} ({ClientName}) via header {HeaderName}",
					client.ClientId,
					client.ClientName,
					headerName);
			}

			return ApiKeyResolveResult.Success(client);
		}

		// No matching key found
		if (this._logger.IsEnabled(LogLevel.Debug)) {
			this._logger.LogDebug(
				"API key not found for header {HeaderName}",
				headerName);
		}

		return ApiKeyResolveResult.NotFound();
	}
}
