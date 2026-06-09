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
internal sealed class SourceDispatchingApiKeyClientResolver(
	IApiKeyClientResolver scan,
	IApiKeySourceCatalog catalog,
	IApiKeyDenylist denylist,
	ApiKeyRevocationReadiness readiness,
	IServiceProvider services,
	ILogger<SourceDispatchingApiKeyClientResolver> logger) : IApiKeyClientResolver {

	private readonly bool _hasAddressableStores = catalog.Sources.Any(s => s.IsAddressableOnly);

	/// <inheritdoc/>
	public IReadOnlySet<string> SupportedHeaders => scan.SupportedHeaders;

	/// <inheritdoc/>
	public async Task<ApiKeyResolveResult> ResolveAsync(
		string providedKey,
		ApiKeyLookupContext context,
		CancellationToken cancellationToken = default) {

		// Revocation gate (ADR-0020 §8): if the denylist is not authoritative yet — boot hydration is
		// incomplete or faulted with AllowFaultedDenylist off — fail closed before evaluating any
		// credential. We cannot prove the presented key is not revoked, so authenticating it would risk
		// honoring a revoked credential. The handler maps this to a 503 (retry), not a 401.
		if (!readiness.IsReady) {
			if (logger.IsEnabled(LogLevel.Warning)) {
				logger.LogWarning(
					"ApiKey revocation denylist is not authoritative; failing authentication closed (503).");
			}

			return ApiKeyResolveResult.RevocationUnavailable();
		}

		// Addressable dispatch: an explicit X-Api-Source routes O(1) to that store's resolver.
		if (!string.IsNullOrEmpty(context.RequestedSource)) {
			var resolvedSource = catalog.FindByRef(context.RequestedSource);
			if (resolvedSource is null) {
				// Unknown source — never enumerate valid sources; treat as a generic miss.
				if (logger.IsEnabled(LogLevel.Debug)) {
					logger.LogDebug("X-Api-Source did not match any registered store.");
				}
				return ApiKeyResolveResult.NotFound();
			}

			var resolver = services.GetKeyedService<IApiKeyClientResolver>(resolvedSource.SourceRef);
			if (resolver is null) {
				return ApiKeyResolveResult.Failed("API key source is not resolvable.");
			}

			// Enrich the context with the resolved source so the store's resolver/validator scope the
			// lookup to THIS store.
			var routedContext = new ApiKeyLookupContext(
				context.Transport, context.HeaderName, context.Headers, context.RequestedSource, resolvedSource);

			// A throwing store resolver fails closed to a miss (never a 500); cancellation propagates.
			return this.RejectIfRevoked(await ApiKeyResolverGuard.SafeResolveAsync(
				resolver, providedKey, routedContext, logger, cancellationToken));
		}

		// No routing signal: blind-scan the cheap (static) path only. Addressable stores are excluded.
		var result = await ApiKeyResolverGuard.SafeResolveAsync(
			scan, providedKey, context, logger, cancellationToken);
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
	/// takes effect even within a cache entry's TTL. Returns a non-descript NotFound.
	/// </summary>
	/// <remarks>
	/// Fail-closed on an anomalous success: <see cref="ApiKeyResolveResult.Success"/> forbids a null
	/// client, so a success carrying no client is a contract violation from a custom resolver. Rather
	/// than pass it through to be caught downstream — and skip the revocation check while doing so — we
	/// reject it here. A revocation decision must never be made on an absent identity.
	/// </remarks>
	private ApiKeyResolveResult RejectIfRevoked(ApiKeyResolveResult result) {
		if (!result.IsSuccess) {
			return result;
		}

		if (result.Client is null) {
			logger.LogWarning(
				"API key resolution reported success with no client; rejecting (fail closed). " +
				"A resolver must return ApiKeyResolveResult.Success(client) with a non-null client.");
			return ApiKeyResolveResult.NotFound();
		}

		if (denylist.IsRevoked(result.Client.ClientId)) {
			if (logger.IsEnabled(LogLevel.Debug)) {
				logger.LogDebug("API key for client {ClientId} is revoked (denylist).", result.Client.ClientId);
			}

			return ApiKeyResolveResult.NotFound();
		}

		return result;
	}

}
