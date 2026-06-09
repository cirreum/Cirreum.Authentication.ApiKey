namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// The default (un-named) API key source declared via <c>ApiKeyOptions.AddDefaultSource&lt;T&gt;(...)</c>.
/// At most one per provider. Unlike a named source it is <em>not</em> addressed by <c>X-Api-Source</c>;
/// it is the fallback the dispatcher uses when no source is addressed (and after static configured keys
/// are tried). Captured at composition time.
/// </summary>
/// <param name="ResolverType">The app's <c>IApiKeyClientResolver</c> implementation for the default source.</param>
/// <param name="RequireClientId">Whether the dispatcher requires an <c>X-Client-Id</c> index before
/// invoking the default resolver (rejecting a request without one as a non-descript <c>400</c>).</param>
/// <param name="Caching">Optional caching configuration; when set, the resolver is wrapped in a
/// <see cref="CachingApiKeyClientResolver"/>.</param>
internal sealed record ApiKeyDefaultSourceRegistration(
	Type ResolverType,
	bool RequireClientId,
	Action<ApiKeySourceCachingOptions>? Caching);
