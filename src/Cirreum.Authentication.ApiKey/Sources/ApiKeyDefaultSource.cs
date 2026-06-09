namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Runtime holder for the resolved default source (registered as a singleton only when
/// <c>AddDefaultSource</c> was called). Carries the ready-to-use resolver (already caching-wrapped if
/// configured) and whether an <c>X-Client-Id</c> index is required. The <see cref="ApiKeySourceDispatcher"/>
/// reads this as the no-<c>X-Api-Source</c> fallback.
/// </summary>
/// <param name="Resolver">The default source's resolver (caching-wrapped if configured).</param>
/// <param name="RequireClientId">Whether the dispatcher must see an <c>X-Client-Id</c> before invoking it.</param>
internal sealed record ApiKeyDefaultSource(
	IApiKeyClientResolver Resolver,
	bool RequireClientId);
