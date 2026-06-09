namespace Cirreum.Authentication.ApiKey;

using Microsoft.Extensions.Logging;

/// <summary>
/// Wraps an <see cref="IApiKeyClientResolver"/> invocation so a throwing resolver — a custom store, a
/// transient backing-store fault, an NRE in third-party code — fails closed to a non-descript miss
/// rather than surfacing a <c>500</c>. A thrown exception must never become an availability oracle or
/// leak internals on the auth path. Genuine request cancellation is re-thrown so request-abort still
/// propagates; any other exception (including an unrelated <see cref="OperationCanceledException"/>) is
/// logged and contained.
/// </summary>
internal static class ApiKeyResolverGuard {

	public static async Task<ApiKeyResolveResult> SafeResolveAsync(
		IApiKeyClientResolver resolver,
		string providedKey,
		ApiKeyLookupContext context,
		ILogger logger,
		CancellationToken cancellationToken) {

		try {
			return await resolver.ResolveAsync(providedKey, context, cancellationToken);
		} catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
			// Genuine request-abort — let it propagate.
			throw;
		} catch (Exception ex) {
			logger.LogError(
				ex,
				"API key resolver {ResolverType} threw; treating as a miss (fail closed).",
				resolver.GetType().Name);
			return ApiKeyResolveResult.NotFound();
		}
	}
}
