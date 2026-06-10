namespace Cirreum.Authentication.ApiKey;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Bridges a singleton resolver registration to a per-request app resolver: on each
/// <see cref="ResolveAsync"/> it opens a fresh DI scope, resolves the app's
/// <see cref="IApiKeyClientResolver"/> (registered <em>scoped</em>) from it, runs the resolution, and
/// disposes the scope. This is what lets <c>AddDefaultSource</c> / <c>AddNamedSource</c> resolvers depend
/// on scoped services (a <c>DbContext</c>, an <c>IRepository</c>, an <c>ITenantContext</c>) without being
/// captured for the process lifetime on the root container — the classic captive-dependency anti-pattern
/// that, with scope validation off (the default in Production), would otherwise bleed one request's
/// scoped state across every request and tenant on the auth hot path (N10).
/// </summary>
/// <remarks>
/// A fresh scope per resolution (rather than the ambient request scope) keeps credential resolution's
/// data access isolated from the request's unit of work, and keeps this type a safe singleton: it holds
/// only the singleton <see cref="IServiceScopeFactory"/> and the resolver's <see cref="Type"/>. The
/// returned <see cref="ApiKeyResolveResult"/> carries only value data (no scope-bound resources), so it
/// remains valid after the scope is disposed. A caching decorator can sit in front so only cache misses
/// pay the scope cost.
/// </remarks>
internal sealed class ScopedApiKeyClientResolver(
	IServiceScopeFactory scopeFactory,
	Type resolverType
) : IApiKeyClientResolver {

	/// <inheritdoc/>
	public async Task<ApiKeyResolveResult> ResolveAsync(
		string providedKey,
		ApiKeyLookupContext context,
		CancellationToken cancellationToken = default) {

		await using var scope = scopeFactory.CreateAsyncScope();
		var inner = (IApiKeyClientResolver)scope.ServiceProvider.GetRequiredService(resolverType);
		return await inner.ResolveAsync(providedKey, context, cancellationToken);
	}
}
