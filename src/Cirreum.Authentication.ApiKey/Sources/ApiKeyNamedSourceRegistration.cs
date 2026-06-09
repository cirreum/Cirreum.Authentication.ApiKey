namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// A named, addressable API key source declared via <c>ApiKeyOptions.AddNamedSource&lt;T&gt;(...)</c>.
/// Captured at composition time; the <see cref="ResolverType"/> is registered in DI keyed by the
/// source's derived <c>SourceRef</c> for addressable dispatch (ADR-0020 §4/§6).
/// </summary>
/// <param name="FriendlyName">The code-given source name (input to the SourceRef derivation).</param>
/// <param name="ResolverType">The app's <c>IApiKeyClientResolver</c> implementation for this source.</param>
/// <param name="RequireClientId">Whether the dispatcher requires an <c>X-Client-Id</c> index for this
/// source (rejecting a request without one as a non-descript <c>400</c> before invoking the resolver).</param>
/// <param name="Caching">Optional caching configuration; when set, the resolver is wrapped in a
/// <see cref="CachingApiKeyClientResolver"/>.</param>
internal sealed record ApiKeyNamedSourceRegistration(
	string FriendlyName,
	Type ResolverType,
	bool RequireClientId,
	Action<ApiKeySourceCachingOptions>? Caching);
