namespace Cirreum.Authentication.ApiKey.Tests;

/// <summary>
/// Proofs that <see cref="ApiKeyResolveResult"/>'s factories set the typed <see cref="ApiKeyResolveOutcome"/>
/// and that <c>IsSuccess</c> / <c>RequiresRouting</c> derive from it (review finding A4 — the composite
/// branches on the enum, not on free-text).
/// </summary>
public sealed class ApiKeyResolveResultTests {

	[Fact]
	public void Success_sets_the_success_outcome_and_client() {
		var client = new ApiKeyClient { ClientId = "c1", ClientName = "C1" };
		var result = ApiKeyResolveResult.Success(client);

		result.Outcome.Should().Be(ApiKeyResolveOutcome.Success);
		result.IsSuccess.Should().BeTrue();
		result.Client.Should().BeSameAs(client);
		result.RequiresRouting.Should().BeFalse();
	}

	[Fact]
	public void NotFound_is_the_only_soft_outcome() {
		var result = ApiKeyResolveResult.NotFound();

		result.Outcome.Should().Be(ApiKeyResolveOutcome.NotFound);
		result.IsSuccess.Should().BeFalse();
	}

	[Theory]
	[InlineData(ApiKeyResolveOutcome.Failed)]
	[InlineData(ApiKeyResolveOutcome.Expired)]
	[InlineData(ApiKeyResolveOutcome.MissingRoutingSignal)]
	[InlineData(ApiKeyResolveOutcome.RevocationUnavailable)]
	public void Non_success_factories_are_not_successful(ApiKeyResolveOutcome outcome) {
		var result = outcome switch {
			ApiKeyResolveOutcome.Failed => ApiKeyResolveResult.Failed("nope"),
			ApiKeyResolveOutcome.Expired => ApiKeyResolveResult.Expired(),
			ApiKeyResolveOutcome.MissingRoutingSignal => ApiKeyResolveResult.MissingRoutingSignal(),
			ApiKeyResolveOutcome.RevocationUnavailable => ApiKeyResolveResult.RevocationUnavailable(),
			_ => throw new InvalidOperationException(),
		};

		result.Outcome.Should().Be(outcome);
		result.IsSuccess.Should().BeFalse();
	}

	[Fact]
	public void RequiresRouting_is_true_only_for_the_missing_routing_signal_outcome() {
		ApiKeyResolveResult.MissingRoutingSignal().RequiresRouting.Should().BeTrue();
		ApiKeyResolveResult.NotFound().RequiresRouting.Should().BeFalse();
		ApiKeyResolveResult.RevocationUnavailable().RequiresRouting.Should().BeFalse();
	}

	[Fact]
	public void Success_rejects_a_null_client() {
		var act = () => ApiKeyResolveResult.Success(null!);
		act.Should().Throw<ArgumentNullException>();
	}
}
