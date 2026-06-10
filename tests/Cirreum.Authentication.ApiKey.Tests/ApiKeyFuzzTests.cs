namespace Cirreum.Authentication.ApiKey.Tests;

using Microsoft.Extensions.Options;

/// <summary>
/// Fuzz proofs that the verification and format paths fail closed — they return <see langword="false"/>
/// / an invalid result on arbitrary or hostile input and never throw (a thrown exception on the auth
/// path is a 500 and an availability oracle). Covers poisoned stored-hash values and garbage presented
/// keys.
/// </summary>
public sealed class ApiKeyFuzzTests {

	private const int Iterations = 20_000;

	private static DefaultApiKeyValidator Validator() =>
		new(Options.Create(new ApiKeyValidationOptions()), [new Sha256ApiKeyHasher(), new Pbkdf2ApiKeyHasher(Pbkdf2ApiKeyHasher.MinIterations)]);

	private static string RandomString(Random rng) {
		var len = rng.Next(0, 80);
		const string pool = "abcdefABCDEF0123456789$-_=+/. \t\n:";
		return string.Create(len, rng, (span, r) => {
			for (var i = 0; i < span.Length; i++) {
				span[i] = pool[r.Next(pool.Length)];
			}
		});
	}

	[Fact]
	public void VerifyKey_never_throws_on_arbitrary_stored_values() {
		var validator = Validator();
		var rng = new Random(20260609);

		for (var i = 0; i < Iterations; i++) {
			var provided = RandomString(rng);
			var stored = RandomString(rng);

			var act = () => validator.VerifyKey(provided, stored);
			act.Should().NotThrow();
			validator.VerifyKey(provided, stored).Should().BeFalse("random values must not verify");
		}
	}

	[Fact]
	public void Both_hashers_never_throw_on_arbitrary_encoded_values() {
		var sha256 = new Sha256ApiKeyHasher();
		var pbkdf2 = new Pbkdf2ApiKeyHasher(Pbkdf2ApiKeyHasher.MinIterations);
		var rng = new Random(987654321);

		for (var i = 0; i < Iterations; i++) {
			var key = RandomString(rng);
			var encoded = RandomString(rng);

			((Action)(() => sha256.Verify(key, encoded))).Should().NotThrow();
			((Action)(() => pbkdf2.Verify(key, encoded))).Should().NotThrow();
		}
	}

	[Fact]
	public void ValidateFormat_never_throws_on_arbitrary_input() {
		var validator = Validator();
		var rng = new Random(424242);

		for (var i = 0; i < Iterations; i++) {
			var key = RandomString(rng);
			((Action)(() => validator.ValidateFormat(key))).Should().NotThrow();
		}
	}
}
