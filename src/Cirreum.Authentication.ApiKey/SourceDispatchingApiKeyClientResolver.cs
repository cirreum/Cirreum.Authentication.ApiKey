namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

/// <summary>
/// The top-level <see cref="IApiKeyClientResolver"/> the handler calls. It implements ADR-0020 §5
/// dispatch: an explicit <c>X-Api-Source</c> routes O(1) to that store's resolver (the only way an
/// addressable-only store is reached), while a request with no routing signal blind-scans the cheap
/// (static) path only — expensive stores are never blind-scanned. A Bearer credential that matches
/// no cheap store while addressable stores exist and no <c>X-Api-Source</c> was supplied yields a
/// non-descript 400 (missing routing signal), never a blind scan of expensive stores.
/// </summary>
internal sealed class SourceDispatchingApiKeyClientResolver : IApiKeyClientResolver {

	private readonly IApiKeyClientResolver _scan;
	private readonly IApiKeySourceCatalog _catalog;
	private readonly IServiceProvider _services;
	private readonly ILogger<SourceDispatchingApiKeyClientResolver> _logger;
	private readonly bool _hasAddressableStores;

	public SourceDispatchingApiKeyClientResolver(
		IApiKeyClientResolver scan,
		IApiKeySourceCatalog catalog,
		IServiceProvider services,
		ILogger<SourceDispatchingApiKeyClientResolver> logger) {

		this._scan = scan;
		this._catalog = catalog;
		this._services = services;
		this._logger = logger;
		this._hasAddressableStores = catalog.Sources.Any(s => s.IsAddressableOnly);
	}

	/// <inheritdoc/>
	public IReadOnlySet<string> SupportedHeaders => this._scan.SupportedHeaders;

	/// <inheritdoc/>
	public async Task<ApiKeyResolveResult> ResolveAsync(
		string providedKey,
		ApiKeyLookupContext context,
		CancellationToken cancellationToken = default) {

		// Addressable dispatch: an explicit X-Api-Source routes O(1) to that store's resolver.
		if (!string.IsNullOrEmpty(context.MatchedSource)) {
			var source = this._catalog.FindByRef(context.MatchedSource);
			if (source is null) {
				// Unknown source — never enumerate valid sources; treat as a generic miss.
				if (this._logger.IsEnabled(LogLevel.Debug)) {
					this._logger.LogDebug("X-Api-Source did not match any registered store.");
				}
				return ApiKeyResolveResult.NotFound();
			}

			var resolver = this._services.GetKeyedService<IApiKeyClientResolver>(source.SourceRef);
			if (resolver is null) {
				return ApiKeyResolveResult.Failed("API key source is not resolvable.");
			}

			// Enrich the context with the resolved source so the store's resolver/validator enforce
			// THIS store's conformance profile (not the provider-global one).
			var routedContext = new ApiKeyLookupContext(
				context.Transport, context.HeaderName, context.Headers, context.MatchedSource, source);

			return await resolver.ResolveAsync(providedKey, routedContext, cancellationToken);
		}

		// No routing signal: blind-scan the cheap (static) path only. Addressable stores are excluded.
		var result = await this._scan.ResolveAsync(providedKey, context, cancellationToken);
		if (result.IsSuccess) {
			return result;
		}

		// A Bearer (ak_-committed) credential that matched no cheap store, while addressable stores
		// exist and no X-Api-Source was supplied, is a missing routing signal → non-descript 400.
		if (this._hasAddressableStores && context.Transport == CredentialTransport.BearerAuthorizationHeader) {
			return ApiKeyResolveResult.MissingRoutingSignal();
		}

		return result;
	}

}
