namespace Cirreum.Authentication.ApiKey.Tests;

using Cirreum.AuthenticationProvider;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

/// <summary>
/// Proofs for <see cref="ApiKeySourceDispatcher"/> — the source router + composition engine: the
/// fail-closed revocation gate (B1), config-first then default-fallback precedence, authoritative
/// X-Api-Source routing (no fall-through — PB1), the X-Client-Id gate, the post-resolution denylist
/// consult, and throwing-source containment (A6).
/// </summary>
public sealed class ApiKeySourceDispatcherTests {

	private const string SourceName = "partner-a";
	private const string StaticKey = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"; // 40 chars — clears the format floor
	private static string SourceRef => ApiKeySourceRef.Derive(SourceName);

	private static ApiKeyDenylist NewDenylist() =>
		new(Options.Create(new ApiKeyRevocationOptions()), NullLogger<ApiKeyDenylist>.Instance);

	private static ApiKeyRevocationReadiness Ready() {
		var r = new ApiKeyRevocationReadiness();
		r.MarkReady();
		return r;
	}

	private static ApiKeySourceCatalog CatalogWithNamedSource(bool requireClientId) {
		var catalog = new ApiKeySourceCatalog();
		catalog.Register(new ApiKeySource { FriendlyName = SourceName, SourceRef = SourceRef, RequireClientId = requireClientId });
		return catalog;
	}

	private static IServiceProvider KeyedServices(IApiKeyClientResolver namedResolver) =>
		new ServiceCollection().AddKeyedSingleton<IApiKeyClientResolver>(SourceRef, namedResolver).BuildServiceProvider();

	private static ConfigurationApiKeyClientResolver ConfigWithKey(string key, string clientId) {
		var registry = new ApiKeyClientRegistry();
		registry.Register(new ApiKeyClientEntry("", key, clientId, clientId, [], CredentialTransport.BearerAuthorizationHeader));
		var validator = new DefaultApiKeyValidator(Options.Create(new ApiKeyValidationOptions()), [new Sha256ApiKeyHasher()]);
		return new ConfigurationApiKeyClientResolver(registry, validator, NullLogger<ConfigurationApiKeyClientResolver>.Instance);
	}

	private static ApiKeyLookupContext Context(string? requestedSource = null, bool withClientId = false) =>
		TestResolvers.Context(
			requestedSource: requestedSource,
			headers: withClientId
				? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { [ApiKeyHeaders.ClientId] = "acme" }
				: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

	private static ApiKeySourceDispatcher Dispatcher(
		ConfigurationApiKeyClientResolver? config = null,
		ApiKeyDefaultSource? defaultSource = null,
		IApiKeySourceCatalog? catalog = null,
		ApiKeyDenylist? denylist = null,
		ApiKeyRevocationReadiness? readiness = null,
		IServiceProvider? services = null) =>
		new(config, defaultSource, catalog ?? new ApiKeySourceCatalog(), denylist ?? NewDenylist(),
			readiness ?? Ready(), services ?? new ServiceCollection().BuildServiceProvider(),
			NullLogger<ApiKeySourceDispatcher>.Instance);

	// ---- Revocation gate (B1) ----

	[Fact]
	public async Task Not_ready_fails_closed_with_RevocationUnavailable_B1() {
		var defaultStub = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client()));
		var dispatcher = Dispatcher(
			defaultSource: new ApiKeyDefaultSource(defaultStub, RequireClientId: false),
			readiness: new ApiKeyRevocationReadiness());

		var result = await dispatcher.ResolveAsync("k", Context());

		result.Outcome.Should().Be(ApiKeyResolveOutcome.RevocationUnavailable);
		defaultStub.Calls.Should().Be(0, "no credential is evaluated while revocation state is unknown");
	}

	// ---- Default source ----

	[Fact]
	public async Task The_default_source_resolves_when_no_X_Api_Source() {
		var dispatcher = Dispatcher(
			defaultSource: new ApiKeyDefaultSource(
				new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("client-1"))), RequireClientId: false));

		var result = await dispatcher.ResolveAsync("k", Context());

		result.IsSuccess.Should().BeTrue();
		result.Client!.ClientId.Should().Be("client-1");
	}

	[Fact]
	public async Task The_default_source_requireClientId_without_the_header_is_a_400() {
		var stub = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client()));
		var dispatcher = Dispatcher(defaultSource: new ApiKeyDefaultSource(stub, RequireClientId: true));

		var result = await dispatcher.ResolveAsync("k", Context(withClientId: false));

		result.Outcome.Should().Be(ApiKeyResolveOutcome.MissingClientIndex);
		stub.Calls.Should().Be(0, "the resolver is never invoked without its required index");
	}

	[Fact]
	public async Task The_default_source_requireClientId_with_the_header_resolves() {
		var dispatcher = Dispatcher(defaultSource: new ApiKeyDefaultSource(
			new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("client-1"))), RequireClientId: true));

		var result = await dispatcher.ResolveAsync("k", Context(withClientId: true));

		result.IsSuccess.Should().BeTrue();
	}

	// ---- Config-first precedence ----

	[Fact]
	public async Task Config_is_tried_before_the_default_source() {
		var defaultStub = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("dynamic")));
		var dispatcher = Dispatcher(
			config: ConfigWithKey(StaticKey, "static-1"),
			defaultSource: new ApiKeyDefaultSource(defaultStub, RequireClientId: false));

		var result = await dispatcher.ResolveAsync(StaticKey, Context());

		result.IsSuccess.Should().BeTrue();
		result.Client!.ClientId.Should().Be("static-1");
		defaultStub.Calls.Should().Be(0, "a configured static key wins; the default source is not consulted");
	}

	[Fact]
	public async Task A_config_miss_falls_through_to_the_default_source() {
		var defaultStub = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("dynamic")));
		var dispatcher = Dispatcher(
			config: ConfigWithKey(StaticKey, "static-1"),
			defaultSource: new ApiKeyDefaultSource(defaultStub, RequireClientId: false));

		// A different (format-valid) key — not the configured one.
		var result = await dispatcher.ResolveAsync("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", Context());

		result.IsSuccess.Should().BeTrue();
		result.Client!.ClientId.Should().Be("dynamic");
		defaultStub.Calls.Should().Be(1);
	}

	[Fact]
	public async Task A_revoked_client_is_rejected_after_a_successful_resolution() {
		var denylist = NewDenylist();
		denylist.Revoke("client-1");
		var dispatcher = Dispatcher(
			defaultSource: new ApiKeyDefaultSource(
				new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("client-1"))), RequireClientId: false),
			denylist: denylist);

		var result = await dispatcher.ResolveAsync("k", Context());

		result.Outcome.Should().Be(ApiKeyResolveOutcome.NotFound, "revocation is consulted even on a resolution hit");
	}

	// ---- Addressed (named) source — authoritative ----

	[Fact]
	public async Task An_explicit_source_routes_to_the_keyed_resolver() {
		var named = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("routed")));
		var dispatcher = Dispatcher(
			catalog: CatalogWithNamedSource(requireClientId: false),
			services: KeyedServices(named),
			defaultSource: new ApiKeyDefaultSource(
				new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("default"))), RequireClientId: false));

		var result = await dispatcher.ResolveAsync("k", Context(requestedSource: SourceRef));

		result.IsSuccess.Should().BeTrue();
		result.Client!.ClientId.Should().Be("routed");
	}

	[Fact]
	public async Task An_addressed_source_does_not_fall_through_to_the_default_PB1() {
		var named = new TestResolvers.Stub(ApiKeyResolveResult.NotFound());
		var defaultStub = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("default")));
		var dispatcher = Dispatcher(
			catalog: CatalogWithNamedSource(requireClientId: false),
			services: KeyedServices(named),
			defaultSource: new ApiKeyDefaultSource(defaultStub, RequireClientId: false));

		var result = await dispatcher.ResolveAsync("k", Context(requestedSource: SourceRef));

		result.Outcome.Should().Be(ApiKeyResolveOutcome.NotFound, "the addressed source is authoritative");
		defaultStub.Calls.Should().Be(0);
	}

	[Fact]
	public async Task An_unknown_source_is_a_generic_miss_no_fall_through_PB2() {
		var defaultStub = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("default")));
		var dispatcher = Dispatcher(
			catalog: CatalogWithNamedSource(requireClientId: false),
			services: KeyedServices(new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("routed")))),
			defaultSource: new ApiKeyDefaultSource(defaultStub, RequireClientId: false));

		var result = await dispatcher.ResolveAsync("k", Context(requestedSource: "UNKNOWNREF000000"));

		result.Outcome.Should().Be(ApiKeyResolveOutcome.NotFound, "an unknown ref never enumerates or falls through");
		defaultStub.Calls.Should().Be(0);
	}

	[Fact]
	public async Task An_addressed_source_requireClientId_without_the_header_is_a_400() {
		var named = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client()));
		var dispatcher = Dispatcher(
			catalog: CatalogWithNamedSource(requireClientId: true),
			services: KeyedServices(named));

		var result = await dispatcher.ResolveAsync("k", Context(requestedSource: SourceRef, withClientId: false));

		result.Outcome.Should().Be(ApiKeyResolveOutcome.MissingClientIndex);
		named.Calls.Should().Be(0);
	}

	[Fact]
	public async Task A_throwing_keyed_source_is_contained_A6() {
		var dispatcher = Dispatcher(
			catalog: CatalogWithNamedSource(requireClientId: false),
			services: KeyedServices(new TestResolvers.Throwing()));

		var result = await dispatcher.ResolveAsync("k", Context(requestedSource: SourceRef));

		result.Outcome.Should().Be(ApiKeyResolveOutcome.NotFound, "a throwing source fails closed to a miss, not a 500");
	}

	// ---- No-match handling ----

	[Fact]
	public async Task No_source_with_named_sources_on_bearer_is_a_missing_routing_signal() {
		var dispatcher = Dispatcher(catalog: CatalogWithNamedSource(requireClientId: false));

		var result = await dispatcher.ResolveAsync("k", Context());

		result.Outcome.Should().Be(ApiKeyResolveOutcome.MissingRoutingSignal);
	}

	[Fact]
	public async Task No_source_without_named_or_default_is_not_found() {
		var dispatcher = Dispatcher();

		var result = await dispatcher.ResolveAsync("k", Context());

		result.Outcome.Should().Be(ApiKeyResolveOutcome.NotFound);
	}
}
