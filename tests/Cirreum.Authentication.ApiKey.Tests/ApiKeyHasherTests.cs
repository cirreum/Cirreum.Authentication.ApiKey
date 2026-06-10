namespace Cirreum.Authentication.ApiKey.Tests;

/// <summary>
/// Proofs for the self-describing hashers: encoded-form shape, round-trip verification, rejection of a
/// foreign-format value, and tamper detection. Each hasher must refuse a value it did not produce
/// (so the validator's tag dispatch can rely on a single hasher answering).
/// </summary>
public sealed class ApiKeyHasherTests {

	[Fact]
	public void Sha256_produces_a_self_describing_encoded_form_and_round_trips() {
		var hasher = new Sha256ApiKeyHasher();
		var encoded = hasher.Hash("a-high-entropy-secret");

		encoded.Should().StartWith("sha256$");
		encoded.Split('$').Should().HaveCount(3);
		hasher.Verify("a-high-entropy-secret", encoded).Should().BeTrue();
		hasher.Verify("a-different-secret", encoded).Should().BeFalse();
	}

	[Fact]
	public void Pbkdf2_produces_a_self_describing_encoded_form_with_iterations_and_round_trips() {
		var hasher = new Pbkdf2ApiKeyHasher(Pbkdf2ApiKeyHasher.MinIterations);
		var encoded = hasher.Hash("a-high-entropy-secret");

		encoded.Should().StartWith($"pbkdf2${Pbkdf2ApiKeyHasher.MinIterations}$");
		encoded.Split('$').Should().HaveCount(4);
		hasher.Verify("a-high-entropy-secret", encoded).Should().BeTrue();
		hasher.Verify("a-different-secret", encoded).Should().BeFalse();
	}

	[Fact]
	public void Pbkdf2_constructor_rejects_an_iteration_count_below_the_floor() {
		// A misconfigured work factor cannot produce a weak hasher (N1).
		var act = () => new Pbkdf2ApiKeyHasher(Pbkdf2ApiKeyHasher.MinIterations - 1);
		act.Should().Throw<ArgumentOutOfRangeException>();
	}

	[Fact]
	public void Pbkdf2_rejects_a_stored_iteration_count_below_the_floor() {
		// A store value poisoned/downgraded toward a trivial iteration count fails closed, not verifies (N1).
		var downgraded = $"pbkdf2${Pbkdf2ApiKeyHasher.MinIterations - 1}$" +
			Convert.ToBase64String(new byte[32]) + "$" + Convert.ToBase64String(new byte[32]);

		new Pbkdf2ApiKeyHasher(Pbkdf2ApiKeyHasher.MinIterations).Verify("k", downgraded).Should().BeFalse();
	}

	[Fact]
	public void Each_hasher_refuses_a_foreign_format() {
		var sha256 = new Sha256ApiKeyHasher();
		var pbkdf2 = new Pbkdf2ApiKeyHasher(Pbkdf2ApiKeyHasher.MinIterations);

		sha256.Verify("k", pbkdf2.Hash("k")).Should().BeFalse();
		pbkdf2.Verify("k", sha256.Hash("k")).Should().BeFalse();
	}

	[Fact]
	public void Sha256_verify_is_false_for_a_tampered_encoded_value() {
		var hasher = new Sha256ApiKeyHasher();
		var encoded = hasher.Hash("k");
		var tampered = encoded[..^4] + (encoded.EndsWith("AAAA") ? "BBBB" : "AAAA");

		hasher.Verify("k", tampered).Should().BeFalse();
	}

	[Fact]
	public void Pbkdf2_rejects_a_stored_iteration_count_above_the_ceiling() {
		// A hostile store value cannot amplify per-verify work into a CPU DoS.
		var poisoned = $"pbkdf2${Pbkdf2ApiKeyHasher.MaxIterations + 1}$" +
			Convert.ToBase64String(new byte[32]) + "$" + Convert.ToBase64String(new byte[32]);

		new Pbkdf2ApiKeyHasher(Pbkdf2ApiKeyHasher.MinIterations).Verify("k", poisoned).Should().BeFalse();
	}
}
