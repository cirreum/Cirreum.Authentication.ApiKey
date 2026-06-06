namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// A registered API key source (a "key set" — ADR-0020 §4): a backing store of keys with its own
/// conformance profile and an opaque, derived <see cref="SourceRef"/> for routing.
/// </summary>
public interface IApiKeySource {

	/// <summary>The code-given friendly name. Stays in code; never reaches the wire.</summary>
	string FriendlyName { get; }

	/// <summary>The opaque, derived wire reference (the <c>X-Api-Source</c> value).</summary>
	string SourceRef { get; }

	/// <summary>The conformance profile this source enforces.</summary>
	ApiKeyConformanceProfile Profile { get; }

	/// <summary>The backing kind (static/scannable vs dynamic/addressable).</summary>
	ApiKeySourceKind Kind { get; }

	/// <summary>
	/// Whether this source is reachable only by explicit <c>X-Api-Source</c> address and must never be
	/// part of the blind fallback scan (the CPU-DoS guarantee). True for all dynamic stores.
	/// </summary>
	bool IsAddressableOnly { get; }

}
