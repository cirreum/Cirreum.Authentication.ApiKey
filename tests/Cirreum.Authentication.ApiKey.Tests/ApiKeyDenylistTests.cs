namespace Cirreum.Authentication.ApiKey.Tests;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

/// <summary>
/// Proofs for <see cref="ApiKeyDenylist"/> (review group D): basic revoke/consult, evict-on-expiry
/// (never un-revoking a live credential), and the bounded cap that refuses rather than evicts a live
/// entry or silently drops.
/// </summary>
public sealed class ApiKeyDenylistTests {

	private static ApiKeyDenylist Denylist(int maxEntries = 1_000_000) =>
		new(Options.Create(new ApiKeyRevocationOptions { MaxDenylistEntries = maxEntries }),
			NullLogger<ApiKeyDenylist>.Instance);

	[Fact]
	public void Revoke_then_IsRevoked_is_true_for_a_no_expiry_entry() {
		var denylist = Denylist();
		denylist.Revoke("cred-1");

		denylist.IsRevoked("cred-1").Should().BeTrue();
		denylist.IsRevoked("cred-2").Should().BeFalse();
		denylist.IsRevoked("").Should().BeFalse();
	}

	[Fact]
	public void An_entry_whose_credential_has_expired_is_evicted_on_read() {
		var denylist = Denylist();
		denylist.Revoke("cred-1", DateTimeOffset.UtcNow.AddMinutes(-1));

		denylist.IsRevoked("cred-1").Should().BeFalse("the credential is already dead, so the entry is reclaimed");
	}

	[Fact]
	public void An_entry_with_a_future_expiry_remains_revoked() {
		var denylist = Denylist();
		denylist.Revoke("cred-1", DateTimeOffset.UtcNow.AddMinutes(5));

		denylist.IsRevoked("cred-1").Should().BeTrue();
	}

	[Fact]
	public void Refining_an_existing_entry_expiry_keeps_it_revoked() {
		var denylist = Denylist();
		denylist.Revoke("cred-1");
		denylist.Revoke("cred-1", DateTimeOffset.UtcNow.AddMinutes(5));

		denylist.IsRevoked("cred-1").Should().BeTrue();
	}

	[Fact]
	public void At_cap_a_new_revocation_is_refused_but_existing_entries_stay_revoked_D() {
		var denylist = Denylist(maxEntries: 2);
		denylist.Revoke("cred-1");
		denylist.Revoke("cred-2");

		denylist.Revoke("cred-3"); // over cap, nothing safe to reclaim

		denylist.IsRevoked("cred-1").Should().BeTrue("a live revoked entry is never evicted to make room");
		denylist.IsRevoked("cred-2").Should().BeTrue();
		denylist.IsRevoked("cred-3").Should().BeFalse("the new revocation is refused, never honored beyond the cap");
	}

	[Fact]
	public void At_cap_an_expired_entry_is_reclaimed_to_admit_a_new_revocation_D() {
		var denylist = Denylist(maxEntries: 2);
		denylist.Revoke("expired", DateTimeOffset.UtcNow.AddMinutes(-1)); // dead credential
		denylist.Revoke("live");                                          // no expiry

		denylist.Revoke("new-one"); // sweep reclaims "expired", admits "new-one"

		denylist.IsRevoked("new-one").Should().BeTrue();
		denylist.IsRevoked("live").Should().BeTrue();
		denylist.IsRevoked("expired").Should().BeFalse();
	}
}
