namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// A dynamic (database-backed) key store declared via <c>ApiKeyOptions.AddDynamicStore&lt;T&gt;(...)</c>.
/// Captured at composition time; the <see cref="ResolverType"/> is registered in DI keyed by the
/// store's derived <c>SourceRef</c> for addressable dispatch (ADR-0020 §4/§6).
/// </summary>
/// <param name="FriendlyName">The code-given store name (input to the SourceRef derivation).</param>
/// <param name="Profile">The conformance profile this store enforces.</param>
/// <param name="ResolverType">The app's <c>IApiKeyClientResolver</c> implementation for this store.</param>
internal sealed record ApiKeyDynamicStoreRegistration(
	string FriendlyName,
	ApiKeyConformanceProfile Profile,
	Type ResolverType);
