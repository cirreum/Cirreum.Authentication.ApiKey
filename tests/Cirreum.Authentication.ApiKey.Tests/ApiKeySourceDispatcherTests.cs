namespace Cirreum.Authentication.ApiKey.Tests;

using Cirreum.AuthenticationProvider;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

/// <summary>
/// Proofs for <see cref="ApiKeySourceDispatcher"/> — the source router + composition engine (routing
/// ONLY): config-first then default-fallback precedence, authoritative X-Api-Source routing (no
/// fall-through — PB1), the X-Client-Id gate, and throwing-source containment (A6). Revocation,
/// readiness, and expiry are enforced by the handler chokepoint (see ApiKeyAuthenticationHandlerTests),
/// not here.
/// </summary>
public sealed class ApiKeySourceDispatcherTests {

	private const string SourceName = "partner-a";
	private const string StaticKey = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"; // 40 chars — clears the format floor
	private static string SourceRef => ApiKeySourceRef.Derive(SourceName);

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
		IServiceProvider? services = null) =>
		new(config, defaultSource, catalog ?? new ApiKeySourceCatalog(),
			services ?? new ServiceCollection().BuildServiceProvider(),
			NullLogger<ApiKeySourceDispatcher>.Instance);

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
	public async Task A_config_format_reject_falls_through_to_the_default_source_N9() {
		// A too-short key fails the config resolver's format check — that must be a soft miss (NotFound), not
		// a chain-stopping Failed, so the dynamic default source still gets a chance at it.
		var defaultStub = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("dynamic")));
		var dispatcher = Dispatcher(
			config: ConfigWithKey(StaticKey, "static-1"),
			defaultSource: new ApiKeyDefaultSource(defaultStub, RequireClientId: false));

		var result = await dispatcher.ResolveAsync("short", Context());

		result.IsSuccess.Should().BeTrue();
		result.Client!.ClientId.Should().Be("dynamic");
		defaultStub.Calls.Should().Be(1, "the config format reject did not short-circuit the chain");
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

	[Fact]
	public async Task Cancellation_propagates() {
		using var cts = new CancellationTokenSource();
		await cts.CancelAsync();
		var dispatcher = Dispatcher(
			catalog: CatalogWithNamedSource(requireClientId: false),
			services: KeyedServices(new TestResolvers.CancelObserving()));

		var act = () => dispatcher.ResolveAsync("k", Context(requestedSource: SourceRef), cts.Token);

		await act.Should().ThrowAsync<OperationCanceledException>();
	}

	// ---- Composition variations: config-only / named-only / config+named / all three ----

	[Fact]
	public async Task Config_only_resolves_a_configured_key_and_misses_otherwise() {
		var dispatcher = Dispatcher(config: ConfigWithKey(StaticKey, "static-1"));

		var hit = await dispatcher.ResolveAsync(StaticKey, Context());
		hit.IsSuccess.Should().BeTrue();
		hit.Client!.ClientId.Should().Be("static-1");

		// A different (format-valid) key with no default/named source behind it → a plain 401, not a 400.
		var miss = await dispatcher.ResolveAsync("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", Context());
		miss.Outcome.Should().Be(ApiKeyResolveOutcome.NotFound);
	}

	[Fact]
	public async Task Named_only_routes_on_X_Api_Source_and_demands_it_otherwise() {
		var named = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("named-1")));
		var dispatcher = Dispatcher(
			catalog: CatalogWithNamedSource(requireClientId: false),
			services: KeyedServices(named));

		var routed = await dispatcher.ResolveAsync("k", Context(requestedSource: SourceRef));
		routed.Client!.ClientId.Should().Be("named-1");

		// No address, named sources exist, Bearer → must address one (400), never blind-scan.
		var unaddressed = await dispatcher.ResolveAsync("k", Context());
		unaddressed.Outcome.Should().Be(ApiKeyResolveOutcome.MissingRoutingSignal);
	}

	[Fact]
	public async Task Config_plus_named_serves_config_unaddressed_and_named_when_addressed() {
		var named = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("named-1")));
		var dispatcher = Dispatcher(
			config: ConfigWithKey(StaticKey, "static-1"),
			catalog: CatalogWithNamedSource(requireClientId: false),
			services: KeyedServices(named));

		var viaConfig = await dispatcher.ResolveAsync(StaticKey, Context());
		viaConfig.Client!.ClientId.Should().Be("static-1");

		var viaNamed = await dispatcher.ResolveAsync("k", Context(requestedSource: SourceRef));
		viaNamed.Client!.ClientId.Should().Be("named-1");
	}

	[Fact]
	public async Task All_three_sources_compose_with_the_right_precedence() {
		var named = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("named-1")));
		var dispatcher = Dispatcher(
			config: ConfigWithKey(StaticKey, "static-1"),
			defaultSource: new ApiKeyDefaultSource(
				new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("default-1"))), RequireClientId: false),
			catalog: CatalogWithNamedSource(requireClientId: false),
			services: KeyedServices(named));

		// Configured static key, no address → config wins.
		(await dispatcher.ResolveAsync(StaticKey, Context())).Client!.ClientId.Should().Be("static-1");

		// Non-static key, no address → falls through to the default source.
		(await dispatcher.ResolveAsync("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", Context())).Client!.ClientId.Should().Be("default-1");

		// Addressed → the named source, authoritatively (config + default not consulted).
		(await dispatcher.ResolveAsync("k", Context(requestedSource: SourceRef))).Client!.ClientId.Should().Be("named-1");
	}
}
