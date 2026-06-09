namespace Cirreum.Authentication.ApiKey.Tests;

using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

/// <summary>
/// Proofs that <see cref="ApiKeyRevocationHealthCheck"/> reports denylist authority correctly (review
/// B1): Healthy when authoritative, Degraded while hydrating or when serving faulted-but-allowed,
/// Unhealthy when faulted and failing closed.
/// </summary>
public sealed class ApiKeyRevocationHealthCheckTests {

	private static async Task<HealthStatus> CheckAsync(ApiKeyRevocationReadiness readiness, bool allowFaulted = false) {
		var check = new ApiKeyRevocationHealthCheck(
			readiness, Options.Create(new ApiKeyRevocationOptions { AllowFaultedDenylist = allowFaulted }));
		var result = await check.CheckHealthAsync(new HealthCheckContext());
		return result.Status;
	}

	[Fact]
	public async Task Authoritative_denylist_is_healthy() {
		var readiness = new ApiKeyRevocationReadiness();
		readiness.MarkReady();

		(await CheckAsync(readiness)).Should().Be(HealthStatus.Healthy);
	}

	[Fact]
	public async Task Still_hydrating_is_degraded() {
		(await CheckAsync(new ApiKeyRevocationReadiness())).Should().Be(HealthStatus.Degraded);
	}

	[Fact]
	public async Task Faulted_and_failing_closed_is_unhealthy_B1() {
		var readiness = new ApiKeyRevocationReadiness();
		readiness.MarkFaulted();

		(await CheckAsync(readiness, allowFaulted: false)).Should().Be(HealthStatus.Unhealthy);
	}

	[Fact]
	public async Task Faulted_but_allowed_is_degraded_B1() {
		var readiness = new ApiKeyRevocationReadiness();
		readiness.MarkFaulted();
		readiness.MarkReady();

		(await CheckAsync(readiness, allowFaulted: true)).Should().Be(HealthStatus.Degraded);
	}
}
