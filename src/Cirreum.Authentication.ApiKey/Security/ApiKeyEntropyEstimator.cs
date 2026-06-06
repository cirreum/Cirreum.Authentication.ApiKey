namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Heuristic estimator of an API key's entropy in bits (ADR-0020 §3). It guards gross mistakes —
/// low character-set diversity and repetition (e.g. <c>"aaaa…"</c>) — by estimating
/// <c>distinct-symbols × log2(character-pool)</c>. It is intentionally conservative and is NOT a
/// substitute for generating keys with <see cref="IApiKeyGenerator"/>, which is the real mitigation.
/// </summary>
public static class ApiKeyEntropyEstimator {

	/// <summary>
	/// Estimates the entropy of <paramref name="apiKey"/> in bits. Returns 0 for null/empty input.
	/// </summary>
	public static int EstimateBits(string? apiKey) {
		if (string.IsNullOrEmpty(apiKey)) {
			return 0;
		}

		var hasLower = false;
		var hasUpper = false;
		var hasDigit = false;
		var hasSymbol = false;
		var distinct = new HashSet<char>();

		foreach (var c in apiKey) {
			distinct.Add(c);
			if (char.IsAsciiLetterLower(c)) {
				hasLower = true;
			} else if (char.IsAsciiLetterUpper(c)) {
				hasUpper = true;
			} else if (char.IsAsciiDigit(c)) {
				hasDigit = true;
			} else {
				hasSymbol = true;
			}
		}

		var pool =
			(hasLower ? 26 : 0) +
			(hasUpper ? 26 : 0) +
			(hasDigit ? 10 : 0) +
			(hasSymbol ? 32 : 0);

		if (pool <= 1) {
			return 0;
		}

		// distinct-symbols × bits-per-symbol: penalizes repetition and low charset diversity while
		// staying generous for high-diversity random keys.
		var bitsPerSymbol = Math.Log2(pool);
		return (int)Math.Floor(distinct.Count * bitsPerSymbol);
	}

}
