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
/// <remarks>
/// This type owns <b>routing only</b>. The security gates — revocation-readiness, the denylist consult,
/// and expiry/cryptoperiod — are enforced by <see cref="ApiKeyAuthenticationHandler"/>, the non-replaceable
/// chokepoint, so they hold even when an app re-registers <see cref="IApiKeyClientResolver"/> (N8). The
/// dispatcher therefore never sees the denylist or the readiness flag.
/// </remarks>
internal sealed class ApiKeySourceDispatcher(
	ConfigurationApiKeyClientResolver? configResolver,
	ApiKeyDefaultSource? defaultSource,
	IApiKeySourceCatalog catalog,
	IServiceProvider services,
	ILogger<ApiKeySourceDispatcher> logger
) : IApiKeyClientResolver {

	private readonly bool _hasNamedSources = catalog.Sources.Count > 0;

	/// <inheritdoc/>
	public async Task<ApiKeyResolveResult> ResolveAsync(
		string providedKey,
		ApiKeyLookupContext context,
		CancellationToken cancellationToken = default) {

		// 1. Addressed source: an explicit X-Api-Source routes O(1) to that source's resolver, authoritatively.
		if (!string.IsNullOrEmpty(context.RequestedSource)) {
			return await this.ResolveAddressedAsync(providedKey, context, cancellationToken);
		}

		// 2. No source addressed — try the cheap static config keys first (no client index needed).
		if (configResolver is not null) {
			var configResult = await ApiKeyResolverGuard.SafeResolveAsync(
				configResolver, providedKey, context, logger, cancellationToken);

			if (configResult.IsSuccess) {
				return configResult;
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
				return defaultResult;
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
		// closed to a miss (never a 500); cancellation propagates. Revocation/expiry are applied by the
		// handler chokepoint, not here.
		return await ApiKeyResolverGuard.SafeResolveAsync(
			resolver, providedKey, routedContext, logger, cancellationToken);
	}

	private static bool HasClientId(ApiKeyLookupContext context) =>
		!string.IsNullOrWhiteSpace(context.GetHeader(ApiKeyHeaders.ClientId));

}
