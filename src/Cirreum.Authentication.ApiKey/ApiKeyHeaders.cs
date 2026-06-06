namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Well-known ApiKey routing header names (ADR-0020 §5/§6). These are not credential transports —
/// they carry routing/index hints alongside the credential.
/// </summary>
public static class ApiKeyHeaders {

	/// <summary>
	/// The store-routing header. Its value is the opaque <c>SourceRef</c> of the target key set
	/// (<see cref="ApiKeySourceRef"/>); required to reach a dynamic (addressable-only) store.
	/// </summary>
	public const string Source = "X-Api-Source";

	/// <summary>
	/// The intra-store client index hint (resolver-side optimization for a shared backing).
	/// </summary>
	public const string ClientId = "X-Client-Id";

}
