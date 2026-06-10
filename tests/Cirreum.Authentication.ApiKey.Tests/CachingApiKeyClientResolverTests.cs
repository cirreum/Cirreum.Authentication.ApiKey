namespace Cirreum.Authentication.ApiKey.Tests;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

/// <summary>
/// Proofs for <see cref="CachingApiKeyClientResolver"/>: positive caching, negative caching off by
/// default (A5), and the routing dimension (X-Api-Source) participating in the cache key so a result
/// for one store never satisfies a lookup for another (A5).
/// </summary>
public sealed class CachingApiKeyClientResolverTests {

	private static CachingApiKeyClientResolver Caching(IApiKeyClientResolver inner, ApiKeySourceCachingOptions? options = null) =>
		new(inner, Options.Create(options ?? new ApiKeySourceCachingOptions()),
			NullLogger<CachingApiKeyClientResolver>.Instance);

	[Fact]
	public async Task A_successful_resolution_is_cached() {
		var inner = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("a")));
		var caching = Caching(inner);

		await caching.ResolveAsync("k", TestResolvers.Context());
		await caching.ResolveAsync("k", TestResolvers.Context());

		inner.Calls.Should().Be(1, "a successful resolution is served from cache on the second lookup");
	}

	[Fact]
	public async Task Negative_caching_is_off_by_default_A5() {
		var inner = new TestResolvers.Stub(ApiKeyResolveResult.NotFound());
		var caching = Caching(inner);

		await caching.ResolveAsync("k", TestResolvers.Context());
		await caching.ResolveAsync("k", TestResolvers.Context());

		inner.Calls.Should().Be(2, "a miss is not cached by default, so a newly valid key is never wrongly rejected");
	}

	[Fact]
	public async Task Negative_caching_when_enabled_caches_a_miss() {
		var inner = new TestResolvers.Stub(ApiKeyResolveResult.NotFound());
		var caching = Caching(inner, new ApiKeySourceCachingOptions { EnableNegativeCaching = true });

		await caching.ResolveAsync("k", TestResolvers.Context());
		await caching.ResolveAsync("k", TestResolvers.Context());

		inner.Calls.Should().Be(1);
	}

	[Fact]
	public async Task The_cache_key_includes_the_routing_dimension_A5() {
		var inner = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("a")));
		var caching = Caching(inner);

		await caching.ResolveAsync("k", TestResolvers.Context(requestedSource: "src-a"));
		await caching.ResolveAsync("k", TestResolvers.Context(requestedSource: "src-b"));

		inner.Calls.Should().Be(2, "the same key under a different store must not hit the other store's cache entry");
	}

	[Fact]
	public async Task The_same_routing_dimension_and_key_hits_the_cache() {
		var inner = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("a")));
		var caching = Caching(inner);

		await caching.ResolveAsync("k", TestResolvers.Context(requestedSource: "src-a"));
		await caching.ResolveAsync("k", TestResolvers.Context(requestedSource: "src-a"));

		inner.Calls.Should().Be(1);
	}

	[Fact]
	public async Task The_cache_key_includes_the_client_index_N16() {
		// The same key string presented under two different X-Client-Id values must NOT collide on one
		// cache entry — otherwise one client could be authenticated as the other within the TTL.
		var inner = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("a")));
		var caching = Caching(inner);

		await caching.ResolveAsync("k", ContextWithClientId("acme"));
		await caching.ResolveAsync("k", ContextWithClientId("globex"));

		inner.Calls.Should().Be(2, "the same key under a different client index must not hit the other client's entry");
	}

	private static ApiKeyLookupContext ContextWithClientId(string clientId) =>
		TestResolvers.Context(headers: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
			[ApiKeyHeaders.ClientId] = clientId,
		});
}
