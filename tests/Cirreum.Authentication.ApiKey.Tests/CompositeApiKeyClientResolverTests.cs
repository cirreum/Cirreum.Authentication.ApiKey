namespace Cirreum.Authentication.ApiKey.Tests;

using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Proofs for <see cref="CompositeApiKeyClientResolver"/> chain semantics: NotFound is the only
/// outcome that advances to the next resolver (A4), a throwing resolver is contained to a miss (A6),
/// header filtering, and cancellation propagation.
/// </summary>
public sealed class CompositeApiKeyClientResolverTests {

	private static CompositeApiKeyClientResolver Composite(params IApiKeyClientResolver[] resolvers) =>
		new(resolvers, NullLogger<CompositeApiKeyClientResolver>.Instance);

	[Fact]
	public async Task The_first_successful_resolver_wins_and_short_circuits() {
		var first = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("a")));
		var second = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("b")));

		var result = await Composite(first, second).ResolveAsync("k", TestResolvers.Context());

		result.IsSuccess.Should().BeTrue();
		result.Client!.ClientId.Should().Be("a");
		second.Calls.Should().Be(0);
	}

	[Fact]
	public async Task A_not_found_advances_to_the_next_resolver() {
		var first = new TestResolvers.Stub(ApiKeyResolveResult.NotFound());
		var second = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("b")));

		var result = await Composite(first, second).ResolveAsync("k", TestResolvers.Context());

		result.IsSuccess.Should().BeTrue();
		result.Client!.ClientId.Should().Be("b");
		first.Calls.Should().Be(1);
		second.Calls.Should().Be(1);
	}

	[Theory]
	[InlineData(true)]   // Failed
	[InlineData(false)]  // Expired
	public async Task A_definitive_failure_stops_the_chain_A4(bool failed) {
		var hard = new TestResolvers.Stub(failed ? ApiKeyResolveResult.Failed("bad") : ApiKeyResolveResult.Expired());
		var next = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("b")));

		var result = await Composite(hard, next).ResolveAsync("k", TestResolvers.Context());

		result.IsSuccess.Should().BeFalse();
		next.Calls.Should().Be(0, "a non-NotFound outcome is a definitive answer for the credential");
	}

	[Fact]
	public async Task A_resolver_that_does_not_support_the_header_is_skipped() {
		var wrongHeader = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("a")), "X-Other");
		var match = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("b")), "Authorization");

		var result = await Composite(wrongHeader, match).ResolveAsync("k", TestResolvers.Context("Authorization"));

		result.Client!.ClientId.Should().Be("b");
		wrongHeader.Calls.Should().Be(0);
	}

	[Fact]
	public async Task A_throwing_resolver_is_contained_and_the_chain_continues_A6() {
		var throwing = new TestResolvers.Throwing();
		var next = new TestResolvers.Stub(ApiKeyResolveResult.Success(TestResolvers.Client("b")));

		var result = await Composite(throwing, next).ResolveAsync("k", TestResolvers.Context());

		throwing.Calls.Should().Be(1);
		result.IsSuccess.Should().BeTrue("a throwing resolver fails closed to a miss, never a 500");
		result.Client!.ClientId.Should().Be("b");
	}

	[Fact]
	public async Task All_throwing_yields_an_overall_not_found_not_an_exception_A6() {
		var result = await Composite(new TestResolvers.Throwing(), new TestResolvers.Throwing())
			.ResolveAsync("k", TestResolvers.Context());

		result.Outcome.Should().Be(ApiKeyResolveOutcome.NotFound);
	}

	[Fact]
	public async Task Cancellation_propagates() {
		using var cts = new CancellationTokenSource();
		await cts.CancelAsync();

		var act = () => Composite(new TestResolvers.CancelObserving())
			.ResolveAsync("k", TestResolvers.Context(), cts.Token);

		await act.Should().ThrowAsync<OperationCanceledException>();
	}
}
