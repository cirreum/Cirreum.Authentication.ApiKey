namespace Cirreum.Authentication.ApiKey;

using System.Text;

/// <summary>
/// Heuristic estimator of an API key's entropy in bits (ADR-0020 §3). It guards gross mistakes —
/// near-constant keys (e.g. <c>"aaaa…"</c>) and low-period repetitions (e.g. <c>"abab…"</c>) — by scoring
/// <c>effective-length × per-symbol Shannon entropy</c> over the key's <em>observed</em> symbol distribution,
/// where the effective length collapses a whole-number repetition to a single period.
/// </summary>
/// <remarks>
/// <para>
/// Scoring on length against the observed alphabet (rather than a character-class pool capped by the
/// number of distinct symbols) is deliberate: it credits a genuinely strong key in a small alphabet — a
/// 64-char random hex secret carries ~256 bits, a UUID ~120 — instead of rejecting it for "low
/// character-set diversity". Symbols are counted as Unicode scalars (so a surrogate pair counts once and
/// cannot inflate the estimate), not UTF-16 code units.
/// </para>
/// <para>
/// A pure frequency model cannot see sequential structure, so a long low-period pattern (a 50/50 two-symbol
/// <c>"abab…"</c> string has 1 bit/symbol and would otherwise score by its full length). The
/// <em>repetition guard</em> closes that: if the key is an exact whole-number repetition of a shorter unit,
/// only one period's worth of entropy is credited, so a periodic key is rejected regardless of length. It
/// does NOT detect every sequential pattern (a near-periodic or sequential-but-aperiodic key still scores by
/// frequency); it is a gross-mistake guard, NOT a substitute for generating keys with
/// <see cref="IApiKeyGenerator"/>, which is the real mitigation.
/// </para>
/// </remarks>
public static class ApiKeyEntropyEstimator {

	/// <summary>
	/// Estimates the entropy of <paramref name="apiKey"/> in bits. Returns 0 for null/empty input, a single
	/// repeated symbol, or a key that collapses to one symbol per period.
	/// </summary>
	public static int EstimateBits(string? apiKey) {
		if (string.IsNullOrEmpty(apiKey)) {
			return 0;
		}

		// Decompose into Unicode scalars (N2: a surrogate pair is one symbol, not two UTF-16 code units).
		var runes = new List<Rune>(apiKey.Length);
		foreach (var rune in apiKey.EnumerateRunes()) {
			runes.Add(rune);
		}

		var length = runes.Count;

		// Per-symbol Shannon entropy of the observed distribution (0 .. log2(distinct)). This credits a
		// high-diversity key and penalizes one dominated by a few symbols, without the distinct-count cap of
		// a character-class pool (which wrongly rejected strong hex / UUID keys — M1).
		var counts = new Dictionary<Rune, int>();
		foreach (var r in runes) {
			counts[r] = counts.TryGetValue(r, out var n) ? n + 1 : 1;
		}

		// A single distinct symbol (e.g. "aaaa…") carries effectively no entropy.
		if (counts.Count <= 1) {
			return 0;
		}

		var shannon = 0.0;
		foreach (var n in counts.Values) {
			var p = (double)n / length;
			shannon -= p * Math.Log2(p);
		}

		// Repetition guard: collapse a whole-number repetition to one period, so a long low-period pattern
		// ("abab…") is credited only one unit's worth of entropy instead of its full length.
		var effectiveLength = SmallestPeriodLength(runes);

		return (int)Math.Floor(effectiveLength * shannon);
	}

	/// <summary>
	/// Returns the length of the smallest unit the key is an exact whole-number repetition of, or the full
	/// length when the key is not such a repetition. Uses the KMP failure function: the smallest period is
	/// <c>n - failure[n-1]</c>, and the key is an exact repetition of a unit of that length iff
	/// <c>n % period == 0</c> (otherwise it is only partially periodic and gets full-length credit).
	/// </summary>
	private static int SmallestPeriodLength(List<Rune> runes) {
		var n = runes.Count;
		var failure = new int[n];

		for (var i = 1; i < n; i++) {
			var j = failure[i - 1];
			while (j > 0 && !runes[i].Equals(runes[j])) {
				j = failure[j - 1];
			}
			if (runes[i].Equals(runes[j])) {
				j++;
			}
			failure[i] = j;
		}

		var period = n - failure[n - 1];
		return n % period == 0 ? period : n;
	}

}
