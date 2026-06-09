namespace Cirreum.Authentication.ApiKey.Tests;

using Cirreum.AuthenticationProvider;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

/// <summary>
/// Proofs for <see cref="SourceDispatchingApiKeyClientResolver"/>: the fail-closed revocation gate
/// (B1), the post-resolution denylist consult, X-Api-Source routing, the missing-routing-signal
/// result, and throwing-store containment (A6).
/// </summary>
public sealed class SourceDispatchingApiKeyClientResolverTests {

	private const string StoreName = "store-a";
	private static string StoreRef => ApiKeySourceRef.Derive(StoreName);

	private static ApiKeyDenylist NewDenylist() =>
		new(Options.Create(new ApiKeyRevocationOptions()), NullLogger<ApiKeyDenylist>.Instance);

	private static ApiKeySourceCatalog CatalogWithDynamicStore() {
		var catalog = new ApiKeySourceCatalog();
		catalog.Register(new ApiKeySource {
			FriendlyName = StoreName, SourceRef = StoreRef, Kind = ApiKeySourceKind.Dynamic,
		});
		return catalog;
	}

	private static SourceDispatchingApiKeyClientResolver Dispatcher(
		IApiKeyClientResolver scan,
		IApiKeySourceCatalog catalog,
		ApiKeyDenylist denylist,
		ApiKeyRevocationReadiness readiness,
		IServiceProvider? services = null) =>
		new(scan, catalog, denylist, readiness,
			services ?? new ServiceCollection().BuildServiceProvider(),
			NullLogger<SourceDispatchingApiKeyClientResolver>.Instance);

	private static ApiKeyRevocationReadiness Ready() {
		var r = new ApiKeyRevocationReadiness();
		r.MarkReady();
		return r;
	}

	[Fact]
	public async Task Not_ready_fails_closed_with_RevocationUnavailable_B1() {
		var scan = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client()));
		var dispatcher = Dispatcher(scan, new ApiKeySourceCatalog(), NewDenylist(), new ApiKeyRevocationReadiness());

		var result = await dispatcher.ResolveAsync("k", TestResolvers.Context());

		result.Outcome.Should().Be(ApiKeyResolveOutcome.RevocationUnavailable);
		scan.Calls.Should().Be(0, "the credential must not even be evaluated while revocation state is unknown");
	}

	[Fact]
	public async Task Ready_with_a_successful_scan_returns_success() {
		var scan = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("client-1")));
		var dispatcher = Dispatcher(scan, new ApiKeySourceCatalog(), NewDenylist(), Ready());

		var result = await dispatcher.ResolveAsync("k", TestResolvers.Context());

		result.IsSuccess.Should().BeTrue();
		result.Client!.ClientId.Should().Be("client-1");
	}

	[Fact]
	public async Task A_revoked_client_is_rejected_after_a_successful_scan() {
		var denylist = NewDenylist();
		denylist.Revoke("client-1");
		var scan = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("client-1")));
		var dispatcher = Dispatcher(scan, new ApiKeySourceCatalog(), denylist, Ready());

		var result = await dispatcher.ResolveAsync("k", TestResolvers.Context());

		result.Outcome.Should().Be(ApiKeyResolveOutcome.NotFound, "revocation is consulted even on a cache/scan hit");
	}

	[Fact]
	public async Task No_routing_signal_with_addressable_stores_on_bearer_is_a_missing_routing_signal() {
		var scan = new TestResolvers.Stub(ApiKeyResolveResult.NotFound());
		var dispatcher = Dispatcher(scan, CatalogWithDynamicStore(), NewDenylist(), Ready());

		var result = await dispatcher.ResolveAsync("k", TestResolvers.Context());

		result.Outcome.Should().Be(ApiKeyResolveOutcome.MissingRoutingSignal);
	}

	[Fact]
	public async Task No_routing_signal_without_addressable_stores_is_not_found() {
		var scan = new TestResolvers.Stub(ApiKeyResolveResult.NotFound());
		var dispatcher = Dispatcher(scan, new ApiKeySourceCatalog(), NewDenylist(), Ready());

		var result = await dispatcher.ResolveAsync("k", TestResolvers.Context());

		result.Outcome.Should().Be(ApiKeyResolveOutcome.NotFound);
	}

	[Fact]
	public async Task An_explicit_source_routes_to_the_keyed_resolver() {
		var keyed = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("routed")));
		var services = new ServiceCollection()
			.AddKeyedSingleton<IApiKeyClientResolver>(StoreRef, keyed)
			.BuildServiceProvider();
		var scan = new TestResolvers.Stub(ApiKeyResolveResult.NotFound());
		var dispatcher = Dispatcher(scan, CatalogWithDynamicStore(), NewDenylist(), Ready(), services);

		var result = await dispatcher.ResolveAsync("k", TestResolvers.Context(matchedSource: StoreRef));

		result.IsSuccess.Should().BeTrue();
		result.Client!.ClientId.Should().Be("routed");
		scan.Calls.Should().Be(0, "an addressed store does not fall through to the blind scan");
	}

	[Fact]
	public async Task An_unknown_source_is_a_generic_miss() {
		var scan = new TestResolvers.Stub(ApiKeyResolveResult.NotFound());
		var dispatcher = Dispatcher(scan, CatalogWithDynamicStore(), NewDenylist(), Ready());

		var result = await dispatcher.ResolveAsync("k", TestResolvers.Context(matchedSource: "UNKNOWNREF000000"));

		result.Outcome.Should().Be(ApiKeyResolveOutcome.NotFound, "an unknown source never enumerates valid sources");
	}

	[Fact]
	public async Task A_throwing_keyed_resolver_is_contained_A6() {
		var services = new ServiceCollection()
			.AddKeyedSingleton<IApiKeyClientResolver>(StoreRef, new TestResolvers.Throwing())
			.BuildServiceProvider();
		var scan = new TestResolvers.Stub(ApiKeyResolveResult.NotFound());
		var dispatcher = Dispatcher(scan, CatalogWithDynamicStore(), NewDenylist(), Ready(), services);

		var result = await dispatcher.ResolveAsync("k", TestResolvers.Context(matchedSource: StoreRef));

		result.Outcome.Should().Be(ApiKeyResolveOutcome.NotFound, "a throwing store fails closed to a miss, not a 500");
	}
}
