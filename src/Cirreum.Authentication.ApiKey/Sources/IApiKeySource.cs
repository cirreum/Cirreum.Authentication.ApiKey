namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// A registered, addressable API key source (a "key set" — ADR-0020 §4): a named backing store of
/// keys, reached via an explicit <c>X-Api-Source</c> reference. Carries the code-given friendly name,
/// the opaque derived <see cref="SourceRef"/> used on the wire, and whether the source requires an
/// <c>X-Client-Id</c> index on every request.
/// </summary>
public interface IApiKeySource {

	/// <summary>The code-given friendly name. Stays in code; never reaches the wire.</summary>
	string FriendlyName { get; }

	/// <summary>The opaque, derived wire reference (the <c>X-Api-Source</c> value).</summary>
	string SourceRef { get; }

	/// <summary>
	/// Whether a request routed to this source must carry an <c>X-Client-Id</c> header. When
	/// <see langword="true"/>, the dispatcher rejects a request to this source with no client index as a
	/// non-descript <c>400</c> before invoking the resolver — so the resolver does an O(1) indexed
	/// lookup rather than scanning (and hashing) every client's key.
	/// </summary>
	bool RequireClientId { get; }

}
