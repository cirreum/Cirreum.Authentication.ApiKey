namespace Cirreum.Authentication.ApiKey.Tests;

/// <summary>
/// Proofs for <see cref="ApiKeyProviderState"/>: cross-instance key-uniqueness is enforced within a
/// host but isolated between hosts (review A8 — moved off a process-static dictionary), plus the
/// scheme-claim and composition idempotency latches.
/// </summary>
public sealed class ApiKeyProviderStateTests {

	[Fact]
	public void RegisterUniqueKey_rejects_the_same_key_for_a_different_client() {
		var state = new ApiKeyProviderState();
		state.RegisterUniqueKey("shared-secret-key", "instance-a", "client-a");

		var act = () => state.RegisterUniqueKey("shared-secret-key", "instance-b", "client-b");

		act.Should().Throw<InvalidOperationException>().WithMessage("*already registered*client-a*");
	}

	[Fact]
	public void RegisterUniqueKey_allows_distinct_keys() {
		var state = new ApiKeyProviderState();

		var act = () => {
			state.RegisterUniqueKey("key-one", "instance-a", "client-a");
			state.RegisterUniqueKey("key-two", "instance-b", "client-b");
		};

		act.Should().NotThrow();
	}

	[Fact]
	public void Uniqueness_is_isolated_between_separate_state_instances_A8() {
		var hostOne = new ApiKeyProviderState();
		var hostTwo = new ApiKeyProviderState();

		hostOne.RegisterUniqueKey("shared-secret-key", "instance-a", "client-a");

		// A second host (e.g. a parallel integration-test server) registering the same key must NOT
		// collide — the guard is per-host, not process-static.
		var act = () => hostTwo.RegisterUniqueKey("shared-secret-key", "instance-a", "client-a");
		act.Should().NotThrow();
	}

	[Fact]
	public void TryClaimScheme_is_first_caller_wins() {
		var state = new ApiKeyProviderState();

		state.TryClaimScheme("ApiKey:Bearer").Should().BeTrue();
		state.TryClaimScheme("ApiKey:Bearer").Should().BeFalse();
		state.TryClaimScheme("ApiKey:X-Api-Key").Should().BeTrue();
	}

	[Fact]
	public void TryBeginComposition_is_first_caller_wins() {
		var state = new ApiKeyProviderState();

		state.TryBeginComposition().Should().BeTrue();
		state.TryBeginComposition().Should().BeFalse();
	}
}
