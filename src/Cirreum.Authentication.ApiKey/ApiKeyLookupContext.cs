namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;
/// <summary>
/// Per-request context passed to <see cref="IApiKeyClientResolver"/>. Carries the
/// transport the key arrived on, the header name (when arriving on a custom header),
/// and the rest of the request headers for resolvers needing to filter by partner /
/// tenant indicators (e.g., <c>X-Client-Id</c>).
/// </summary>
/// <param name="transport">The transport the key was extracted from.</param>
/// <param name="headerName">The HTTP header name when <paramref name="transport"/> is
/// <see cref="CredentialTransport.CustomHeader"/>; the literal <c>"Authorization"</c>
/// when <paramref name="transport"/> is <see cref="CredentialTransport.BearerAuthorizationHeader"/>.</param>
/// <param name="headers">All non-credential request headers, for filtering / lookup
/// optimization. Excludes the credential value for security.</param>
/// <param name="matchedSource">The resolved store reference from the <c>X-Api-Source</c> routing
/// header (ADR-0020 §6), or <see langword="null"/> when no store was addressed. A resolver over a
/// shared backing can scope its lookup to this source (e.g. <c>WHERE store_ref = @ref</c>).</param>
/// <param name="source">The resolved <see cref="IApiKeySource"/> when an addressable store was routed to
/// (carries the store's conformance profile for per-store validation), or <see langword="null"/>.</param>
public sealed class ApiKeyLookupContext(
	CredentialTransport transport,
	string headerName,
	IReadOnlyDictionary<string, string> headers,
	string? matchedSource = null,
	IApiKeySource? source = null) {

	private readonly IReadOnlyDictionary<string, string> _headers = headers ?? new Dictionary<string, string>();

	/// <summary>
	/// Gets the transport the credential was extracted from.
	/// </summary>
	public CredentialTransport Transport { get; } = transport;

	/// <summary>
	/// Gets the resolved store reference from the <c>X-Api-Source</c> routing header (ADR-0020 §6),
	/// or <see langword="null"/> when no store was addressed. A routing hint only — the resolver still
	/// performs full credential validation; never branch a trust decision on it.
	/// </summary>
	public string? MatchedSource { get; } = matchedSource;

	/// <summary>
	/// Gets the resolved <see cref="IApiKeySource"/> for an addressed store (carrying its conformance
	/// profile), or <see langword="null"/> when no addressable store was routed to.
	/// </summary>
	public IApiKeySource? Source { get; } = source;

	/// <summary>
	/// Gets the HTTP header name the credential arrived on
	/// (<c>"Authorization"</c> for Bearer, or the configured custom header name).
	/// </summary>
	public string HeaderName { get; } = headerName;

	/// <summary>
	/// Gets the value of a specific request header, or <see langword="null"/> when
	/// the header is not present.
	/// </summary>
	/// <remarks>
	/// Common headers used for partner/tenant filtering: <c>X-Client-Id</c>,
	/// <c>X-Tenant-Id</c>, <c>X-Partner-Id</c>.
	/// </remarks>
	public string? GetHeader(string name) {
		return this._headers.TryGetValue(name, out var value) ? value : null;
	}

	/// <summary>
	/// Returns whether a specific request header is present.
	/// </summary>
	public bool HasHeader(string name) => this._headers.ContainsKey(name);

	/// <summary>
	/// Gets all non-credential request headers.
	/// </summary>
	public IReadOnlyDictionary<string, string> Headers => this._headers;

}
