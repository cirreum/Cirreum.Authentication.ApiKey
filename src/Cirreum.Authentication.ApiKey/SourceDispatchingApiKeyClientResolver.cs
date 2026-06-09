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
	private readonly IApiKeyDenylist _denylist;
	private readonly ApiKeyRevocationReadiness _readiness;
	private readonly IServiceProvider _services;
	private readonly ILogger<SourceDispatchingApiKeyClientResolver> _logger;
	private readonly bool _hasAddressableStores;

	public SourceDispatchingApiKeyClientResolver(
		IApiKeyClientResolver scan,
		IApiKeySourceCatalog catalog,
		IApiKeyDenylist denylist,
		ApiKeyRevocationReadiness readiness,
		IServiceProvider services,
		ILogger<SourceDispatchingApiKeyClientResolver> logger) {

		this._scan = scan;
		this._catalog = catalog;
		this._denylist = denylist;
		this._readiness = readiness;
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

		// Revocation gate (ADR-0020 §8): if the denylist is not authoritative yet — boot hydration is
		// incomplete or faulted with AllowFaultedDenylist off — fail closed before evaluating any
		// credential. We cannot prove the presented key is not revoked, so authenticating it would risk
		// honoring a revoked credential. The handler maps this to a 503 (retry), not a 401.
		if (!this._readiness.IsReady) {
			if (this._logger.IsEnabled(LogLevel.Warning)) {
				this._logger.LogWarning(
					"ApiKey revocation denylist is not authoritative; failing authentication closed (503).");
			}

			return ApiKeyResolveResult.RevocationUnavailable();
		}

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

			// Enrich the context with the resolved source so the store's resolver/validator scope the
			// lookup to THIS store.
			var routedContext = new ApiKeyLookupContext(
				context.Transport, context.HeaderName, context.Headers, context.MatchedSource, source);

			// A throwing store resolver fails closed to a miss (never a 500); cancellation propagates.
			return this.RejectIfRevoked(await ApiKeyResolverGuard.SafeResolveAsync(
				resolver, providedKey, routedContext, this._logger, cancellationToken));
		}

		// No routing signal: blind-scan the cheap (static) path only. Addressable stores are excluded.
		var result = await ApiKeyResolverGuard.SafeResolveAsync(
			this._scan, providedKey, context, this._logger, cancellationToken);
		if (result.IsSuccess) {
			return this.RejectIfRevoked(result);
		}

		// A Bearer (ak_-committed) credential that matched no cheap store, while addressable stores
		// exist and no X-Api-Source was supplied, is a missing routing signal → non-descript 400.
		if (this._hasAddressableStores && context.Transport == CredentialTransport.BearerAuthorizationHeader) {
			return ApiKeyResolveResult.MissingRoutingSignal();
		}

		return result;
	}

	/// <summary>
	/// Rejects a successful resolution whose credential is on the denylist (revoked), so revocation
	/// takes effect even within a cache entry's TTL (ADR-0020 §8). Returns a non-descript NotFound.
	/// </summary>
	private ApiKeyResolveResult RejectIfRevoked(ApiKeyResolveResult result) {
		if (result.IsSuccess && result.Client is not null && this._denylist.IsRevoked(result.Client.ClientId)) {
			if (this._logger.IsEnabled(LogLevel.Debug)) {
				this._logger.LogDebug("API key for client {ClientId} is revoked (denylist).", result.Client.ClientId);
			}

			return ApiKeyResolveResult.NotFound();
		}

		return result;
	}

}
