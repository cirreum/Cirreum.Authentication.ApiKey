namespace Cirreum.Authentication.ApiKey.Tests;

/// <summary>
/// Proofs for <see cref="ApiKeyEntropyEstimator"/>: it credits genuinely strong keys in small alphabets
/// (hex / UUID) above the 112-bit look-up-secret floor instead of rejecting them for low character-set
/// diversity (M1), counts Unicode scalars rather than UTF-16 code units so multi-byte glyphs cannot
/// inflate the estimate (N2), and still scores near-constant keys at zero.
/// </summary>
public sealed class ApiKeyEntropyEstimatorTests {

	private const int Floor = 112; // NIST SP 800-63B §5.1.2 look-up-secret entropy floor

	[Fact]
	public void Credits_a_64_char_random_hex_key_above_the_floor_M1() {
		// A realistic (non-periodic) 64-char hex secret ~= 256 bits. The old charset-pool model capped this
		// at ~82 bits and wrongly rejected it.
		var hex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

		ApiKeyEntropyEstimator.EstimateBits(hex).Should().BeGreaterThanOrEqualTo(Floor);
	}

	[Fact]
	public void Rejects_a_long_low_period_repetition_below_the_floor() {
		// A frequency model alone would score "ab" x 100 (200 chars, 1 bit/symbol) at 200 and pass it. The
		// repetition guard credits only one period, so a periodic key is rejected however long it is.
		var periodic = string.Concat(Enumerable.Repeat("ab", 100));

		ApiKeyEntropyEstimator.EstimateBits(periodic).Should().BeLessThan(Floor);
	}

	[Fact]
	public void Credits_a_uuid_above_the_floor_M1() {
		ApiKeyEntropyEstimator.EstimateBits("f47ac10b-58cc-4372-a567-0e02b2c3d479")
			.Should().BeGreaterThanOrEqualTo(Floor);
	}

	[Fact]
	public void Credits_a_generated_base64url_key_above_the_floor() {
		var generated = new DefaultApiKeyGenerator().Generate(256);

		ApiKeyEntropyEstimator.EstimateBits(generated).Should().BeGreaterThanOrEqualTo(Floor);
	}

	[Theory]
	[InlineData("")]
	[InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")] // single repeated symbol
	public void Scores_zero_for_no_or_single_symbol_diversity(string key) {
		ApiKeyEntropyEstimator.EstimateBits(key).Should().Be(0);
	}

	[Fact]
	public void Counts_a_surrogate_pair_as_one_symbol_N2() {
		// Four of the same astral glyph: one distinct scalar → zero entropy. The old model saw two distinct
		// UTF-16 surrogate halves and a flat 32-symbol pool, over-counting it.
		ApiKeyEntropyEstimator.EstimateBits("\U0001F600\U0001F600\U0001F600\U0001F600").Should().Be(0);
	}

	[Fact]
	public void Does_not_let_a_few_astral_glyphs_clear_the_floor_N2() {
		// Eight distinct emoji, each once: ~8 symbols over length 8 ≈ 24 bits — well under the floor. The old
		// surrogate-pair + flat-pool counting could push such a key over it.
		var key = "\U0001F600\U0001F601\U0001F602\U0001F603\U0001F604\U0001F605\U0001F606\U0001F607";

		ApiKeyEntropyEstimator.EstimateBits(key).Should().BeLessThan(Floor);
	}
}
