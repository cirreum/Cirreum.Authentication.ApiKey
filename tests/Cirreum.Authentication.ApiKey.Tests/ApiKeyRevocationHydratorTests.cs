namespace Cirreum.Authentication.ApiKey.Tests;

using System.Runtime.CompilerServices;
using Cirreum.AuthenticationProvider;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

/// <summary>
/// Proofs for the boot-time <see cref="ApiKeyRevocationHydrator"/> fail-closed gate (review B1): a
/// faulted hydration leaves the denylist not-ready unless the operator opts into
/// <c>AllowFaultedDenylist</c>; a clean hydration (including no providers) marks it ready.
/// </summary>
public sealed class ApiKeyRevocationHydratorTests {

	private static ApiKeyRevocationHydrator Hydrator(
		IEnumerable<IRevokedCredentialProvider> providers,
		ApiKeyDenylist denylist,
		ApiKeyRevocationReadiness readiness,
		bool allowFaulted = false) =>
		new(providers, denylist, readiness,
			Options.Create(new ApiKeyRevocationOptions { AllowFaultedDenylist = allowFaulted }),
			NullLogger<ApiKeyRevocationHydrator>.Instance);

	private static ApiKeyDenylist NewDenylist() =>
		new(Options.Create(new ApiKeyRevocationOptions()),
			Options.Create(new ApiKeyValidationOptions()),
			NullLogger<ApiKeyDenylist>.Instance);

	private sealed class YieldingProvider(params string[] ids) : IRevokedCredentialProvider {
		public async IAsyncEnumerable<RevokedCredential> GetRevokedCredentialsAsync(
			[EnumeratorCancellation] CancellationToken cancellationToken = default) {
			foreach (var id in ids) {
				await Task.Yield();
				yield return new RevokedCredential(id);
			}
		}
	}

	private sealed class ExpiringProvider(params (string Id, DateTimeOffset? ExpiresAt)[] entries)
		: IRevokedCredentialProvider {
		public async IAsyncEnumerable<RevokedCredential> GetRevokedCredentialsAsync(
			[EnumeratorCancellation] CancellationToken cancellationToken = default) {
			foreach (var (id, expiresAt) in entries) {
				await Task.Yield();
				yield return new RevokedCredential(id, expiresAt);
			}
		}
	}

	private sealed class FaultingProvider : IRevokedCredentialProvider {
		public async IAsyncEnumerable<RevokedCredential> GetRevokedCredentialsAsync(
			[EnumeratorCancellation] CancellationToken cancellationToken = default) {
			await Task.Yield();
			yield return new RevokedCredential("cred-1");
			throw new InvalidOperationException("revocation source unavailable");
		}
	}

	[Fact]
	public async Task A_hydrated_revocation_carries_the_credential_expiry_through_to_the_denylist() {
		// The whole point of the contract change: an entry hydrated at boot self-evicts on the
		// credential's own expiry, the way one created by a live CredentialRevoked event already
		// does. Previously the hydrator could only say Revoke(id) and the entry was retained until
		// the process restarted.
		var denylist = NewDenylist();
		var expired = DateTimeOffset.UtcNow.AddMinutes(-1);
		var live = DateTimeOffset.UtcNow.AddHours(1);
		var hydrator = Hydrator(
			[new ExpiringProvider(("already-expired", expired), ("still-live", live))],
			denylist,
			new ApiKeyRevocationReadiness());

		await hydrator.StartAsync(CancellationToken.None);

		denylist.IsRevoked("already-expired").Should().BeFalse(
			"the credential's expiry has passed, so it can no longer authenticate anyway");
		denylist.IsRevoked("still-live").Should().BeTrue();
	}

	[Fact]
	public async Task No_providers_marks_the_denylist_ready() {
		var readiness = new ApiKeyRevocationReadiness();

		await Hydrator([], NewDenylist(), readiness).StartAsync(CancellationToken.None);

		readiness.IsReady.Should().BeTrue();
		readiness.Faulted.Should().BeFalse();
	}

	[Fact]
	public async Task A_clean_hydration_populates_the_denylist_and_marks_it_ready() {
		var readiness = new ApiKeyRevocationReadiness();
		var denylist = NewDenylist();

		await Hydrator([new YieldingProvider("cred-1", "cred-2")], denylist, readiness).StartAsync(CancellationToken.None);

		readiness.IsReady.Should().BeTrue();
		denylist.IsRevoked("cred-1").Should().BeTrue();
		denylist.IsRevoked("cred-2").Should().BeTrue();
	}

	[Fact]
	public async Task A_faulted_hydration_fails_closed_by_default_B1() {
		var readiness = new ApiKeyRevocationReadiness();

		await Hydrator([new FaultingProvider()], NewDenylist(), readiness).StartAsync(CancellationToken.None);

		readiness.Faulted.Should().BeTrue();
		readiness.IsReady.Should().BeFalse("a faulted hydration leaves auth failing closed by default");
	}

	[Fact]
	public async Task A_faulted_hydration_serves_when_AllowFaultedDenylist_is_set_B1() {
		var readiness = new ApiKeyRevocationReadiness();

		await Hydrator([new FaultingProvider()], NewDenylist(), readiness, allowFaulted: true)
			.StartAsync(CancellationToken.None);

		readiness.Faulted.Should().BeTrue("the fault is still recorded for the health check");
		readiness.IsReady.Should().BeTrue("the escape hatch opts into availability over the revocation guarantee");
	}
}
