namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

/// <summary>
/// The single top-level <see cref="IApiKeyClientResolver"/> the handler calls — the composition engine
/// and source router in one. It resolves a credential against the right source with no blind scan over
/// dynamic keys (ADR-0020 §5/§6):
/// <list type="number">
///   <item>If an <c>X-Api-Source</c> is supplied, route O(1) to that named source's resolver
///   <b>authoritatively</b> — its answer stands (no fall-through to config or the default).</item>
///   <item>Otherwise, try the cheap static <b>config</b> keys first, then the <b>default</b> dynamic
///   source as a fallback; named sources are never reached without their explicit address.</item>
/// </list>
/// A source declaring <c>RequireClientId</c> is gated on the <c>X-Client-Id</c> header <em>before</em>
/// its resolver runs, so the resolver always does an indexed lookup rather than a scan.
/// </summary>
internal sealed class ApiKeySourceDispatcher(
	ConfigurationApiKeyClientResolver? configResolver,
	ApiKeyDefaultSource? defaultSource,
	IApiKeySourceCatalog catalog,
	IApiKeyDenylist denylist,
	ApiKeyRevocationReadiness readiness,
	IServiceProvider services,
	ILogger<ApiKeySourceDispatcher> logger
) : IApiKeyClientResolver {

	private readonly bool _hasNamedSources = catalog.Sources.Count > 0;

	/// <inheritdoc/>
	public async Task<ApiKeyResolveResult> ResolveAsync(
		string providedKey,
		ApiKeyLookupContext context,
		CancellationToken cancellationToken = default) {

		// Revocation gate (ADR-0020 §8): if the denylist is not authoritative yet — boot hydration is
		// incomplete or faulted with AllowFaultedDenylist off — fail closed before evaluating any
		// credential. The handler maps this to a 503 (retry), not a 401.
		if (!readiness.IsReady) {
			if (logger.IsEnabled(LogLevel.Warning)) {
				logger.LogWarning(
					"ApiKey revocation denylist is not authoritative; failing authentication closed (503).");
			}

			return ApiKeyResolveResult.RevocationUnavailable();
		}

		// 1. Addressed source: an explicit X-Api-Source routes O(1) to that source's resolver, authoritatively.
		if (!string.IsNullOrEmpty(context.RequestedSource)) {
			return await this.ResolveAddressedAsync(providedKey, context, cancellationToken);
		}

		// 2. No source addressed — try the cheap static config keys first (no client index needed).
		if (configResolver is not null) {
			var configResult = await ApiKeyResolverGuard.SafeResolveAsync(
				configResolver, providedKey, context, logger, cancellationToken);

			if (configResult.IsSuccess) {
				return this.RejectIfRevoked(configResult);
			}

			// A definitive failure (e.g. a malformed credential) stands; only a plain miss falls through.
			if (configResult.Outcome is not ApiKeyResolveOutcome.NotFound) {
				return configResult;
			}
		}

		// 3. Fall back to the default dynamic source, if one is registered.
		if (defaultSource is not null) {
			if (defaultSource.RequireClientId && !HasClientId(context)) {
				if (logger.IsEnabled(LogLevel.Debug)) {
					logger.LogDebug("Default API key source requires X-Client-Id; none supplied (400).");
				}

				return ApiKeyResolveResult.MissingClientIndex();
			}

			var defaultResult = await ApiKeyResolverGuard.SafeResolveAsync(
				defaultSource.Resolver, providedKey, context, logger, cancellationToken);

			if (defaultResult.IsSuccess) {
				return this.RejectIfRevoked(defaultResult);
			}

			// Failed / Expired stand; only a plain miss falls through to the no-match handling below.
			if (defaultResult.Outcome is not ApiKeyResolveOutcome.NotFound) {
				return defaultResult;
			}
		}

		// 4. Nothing matched. If addressable named sources exist and a Bearer credential arrived with no
		//    X-Api-Source, that is a missing routing signal → non-descript 400; otherwise a generic 401.
		if (this._hasNamedSources && context.Transport == CredentialTransport.BearerAuthorizationHeader) {
			return ApiKeyResolveResult.MissingRoutingSignal();
		}

		return ApiKeyResolveResult.NotFound();
	}

	private async Task<ApiKeyResolveResult> ResolveAddressedAsync(
		string providedKey,
		ApiKeyLookupContext context,
		CancellationToken cancellationToken) {

		var source = catalog.FindByRef(context.RequestedSource!);
		if (source is null) {
			// Unknown source — never enumerate valid sources, never fall through; treat as a generic miss.
			if (logger.IsEnabled(LogLevel.Debug)) {
				logger.LogDebug("X-Api-Source did not match any registered source.");
			}

			return ApiKeyResolveResult.NotFound();
		}

		// Client-index gate: a source requiring X-Client-Id is rejected (400) before its resolver runs,
		// so the resolver does an indexed lookup rather than scanning (and hashing) every client's key.
		if (source.RequireClientId && !HasClientId(context)) {
			if (logger.IsEnabled(LogLevel.Debug)) {
				logger.LogDebug("API key source '{SourceRef}' requires X-Client-Id; none supplied (400).", source.SourceRef);
			}

			return ApiKeyResolveResult.MissingClientIndex();
		}

		var resolver = services.GetKeyedService<IApiKeyClientResolver>(source.SourceRef);
		if (resolver is null) {
			return ApiKeyResolveResult.Failed("API key source is not resolvable.");
		}

		// Enrich the context with the resolved source so the resolver can scope its lookup to THIS source.
		var routedContext = new ApiKeyLookupContext(
			context.Transport, context.HeaderName, context.Headers, context.RequestedSource, source);

		// Authoritative: the addressed source's answer stands (no fall-through). A throwing resolver fails
		// closed to a miss (never a 500); cancellation propagates.
		return this.RejectIfRevoked(await ApiKeyResolverGuard.SafeResolveAsync(
			resolver, providedKey, routedContext, logger, cancellationToken));
	}

	private static bool HasClientId(ApiKeyLookupContext context) =>
		!string.IsNullOrWhiteSpace(context.GetHeader(ApiKeyHeaders.ClientId));

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
