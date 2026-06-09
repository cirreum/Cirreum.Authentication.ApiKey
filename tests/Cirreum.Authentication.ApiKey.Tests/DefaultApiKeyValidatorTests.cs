namespace Cirreum.Authentication.ApiKey.Tests;

using Microsoft.Extensions.Options;

/// <summary>
/// Proofs for <see cref="DefaultApiKeyValidator"/>: constant-time comparison, the fail-closed
/// self-describing-hash dispatch (review findings A2/A3), the deliberate absence of a request-time
/// entropy gate (A1), the Form-1 configured-key strength floor, and expiry handling.
/// </summary>
public sealed class DefaultApiKeyValidatorTests {

	private static DefaultApiKeyValidator Build(ApiKeyValidationOptions? options = null, params IApiKeyHasher[] hashers) =>
		new(
			Options.Create(options ?? new ApiKeyValidationOptions()),
			hashers.Length > 0 ? hashers : [new Sha256ApiKeyHasher(), new Pbkdf2ApiKeyHasher(1000)]);

	// ---- Constant-time comparison ----

	[Fact]
	public void CompareKeysSecurely_returns_true_for_equal_keys() {
		Build().CompareKeysSecurely("the-same-key-value", "the-same-key-value").Should().BeTrue();
	}

	[Theory]
	[InlineData("key-a", "key-b")]          // same length, different content
	[InlineData("short", "a-much-longer-key")] // different length
	[InlineData("", "non-empty")]            // empty provided
	[InlineData("non-empty", "")]            // empty expected
	public void CompareKeysSecurely_returns_false_for_mismatches(string provided, string expected) {
		Build().CompareKeysSecurely(provided, expected).Should().BeFalse();
	}

	// ---- A1: no request-time entropy oracle ----

	[Fact]
	public void ValidateFormat_does_not_reject_a_low_entropy_key_entropy_is_not_a_request_time_gate() {
		// A long, all-lowercase, low-entropy key is structurally valid at request time — entropy is an
		// issuance concern, never evaluated against a presented credential (would be an oracle).
		var key = new string('a', 40);

		Build().ValidateFormat(key).IsValid.Should().BeTrue();
	}

	[Theory]
	[InlineData("too-short")]                                   // below MinimumKeyLength (32)
	[InlineData("contains spaces which are not allowed here!")] // invalid characters
	public void ValidateFormat_rejects_bad_length_or_characters(string key) {
		Build().ValidateFormat(key).IsValid.Should().BeFalse();
	}

	// ---- Form-1 configured-key strength floor ----

	[Fact]
	public void ValidateConfiguredKeyStrength_rejects_a_long_but_low_entropy_configured_key() {
		var weak = new string('a', 40); // long enough, but ~minimal entropy

		Build().ValidateConfiguredKeyStrength(weak).IsValid.Should().BeFalse();
	}

	[Fact]
	public void ValidateConfiguredKeyStrength_accepts_a_generated_key() {
		var strong = new DefaultApiKeyGenerator().Generate(256);

		Build().ValidateConfiguredKeyStrength(strong).IsValid.Should().BeTrue();
	}

	// ---- A2/A3: fail-closed self-describing-hash dispatch ----

	[Fact]
	public void VerifyKey_round_trips_a_sha256_encoded_hash() {
		var validator = Build();
		var encoded = new Sha256ApiKeyHasher().Hash("the-raw-key");

		validator.VerifyKey("the-raw-key", encoded).Should().BeTrue();
		validator.VerifyKey("the-wrong-key", encoded).Should().BeFalse();
	}

	[Fact]
	public void VerifyKey_round_trips_a_pbkdf2_encoded_hash() {
		var validator = Build();
		var encoded = new Pbkdf2ApiKeyHasher(1000).Hash("the-raw-key");

		validator.VerifyKey("the-raw-key", encoded).Should().BeTrue();
		validator.VerifyKey("the-wrong-key", encoded).Should().BeFalse();
	}

	[Fact]
	public void VerifyKey_rejects_a_bare_non_self_describing_hash_A2() {
		// A legacy bare SHA-256 (no algorithm tag) must be rejected — the fallback path is gone.
		var bare = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
			System.Text.Encoding.UTF8.GetBytes("the-raw-key")));

		Build().VerifyKey("the-raw-key", bare).Should().BeFalse();
	}

	[Theory]
	[InlineData("md5$abc$def")]   // unknown algorithm tag
	[InlineData("$salt$hash")]    // empty tag
	[InlineData("no-separator")]  // no '$'
	public void VerifyKey_rejects_unrecognized_encoded_forms(string stored) {
		Build().VerifyKey("the-raw-key", stored).Should().BeFalse();
	}

	[Fact]
	public void VerifyKey_does_not_cross_dispatch_between_algorithms_A3() {
		// With only the SHA-256 hasher registered, a PBKDF2-tagged value has no hasher to dispatch to and
		// is rejected — no other hasher's Verify is consulted for a foreign tag (algorithm-confusion guard).
		var sha256Only = Build(hashers: new Sha256ApiKeyHasher());
		var pbkdf2Encoded = new Pbkdf2ApiKeyHasher(1000).Hash("the-raw-key");

		sha256Only.VerifyKey("the-raw-key", pbkdf2Encoded).Should().BeFalse();
	}

	[Fact]
	public void VerifyKey_rejects_a_tampered_sha256_hash() {
		var encoded = new Sha256ApiKeyHasher().Hash("the-raw-key");
		var tampered = encoded[..^4] + (encoded.EndsWith("AAAA") ? "BBBB" : "AAAA");

		Build().VerifyKey("the-raw-key", tampered).Should().BeFalse();
	}

	// ---- Expiry ----

	[Fact]
	public void IsExpired_treats_a_missing_expiry_as_valid_unless_RequireExpiry() {
		Build().IsExpired(null).Should().BeFalse();
		Build(new ApiKeyValidationOptions { RequireExpiry = true }).IsExpired(null).Should().BeTrue();
	}

	[Fact]
	public void IsExpired_honors_past_and_future_expiry_and_grace() {
		var validator = Build();

		validator.IsExpired(DateTimeOffset.UtcNow.AddMinutes(-1)).Should().BeTrue();
		validator.IsExpired(DateTimeOffset.UtcNow.AddMinutes(5)).Should().BeFalse();
		validator.IsExpired(DateTimeOffset.UtcNow.AddSeconds(-10), TimeSpan.FromMinutes(1)).Should().BeFalse();
	}
}
