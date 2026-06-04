namespace Cirreum.Authentication;

/// <summary>
/// Well-known HTTP transports (header names) that carry an API key credential. App authors
/// pick from these at composition sites (<c>AddApiKey(opt =&gt; opt.AddTransport(...))</c>) and
/// when authoring custom-header registrations. The constant <em>values</em> are the literal
/// HTTP header names (for <c>Bearer</c>, the value is the <c>Authorization: Bearer</c> scheme
/// token).
/// </summary>
/// <remarks>
/// <para>
/// Each protocol package owns its own <c>Transports</c> + <c>Schemes</c>
/// constants. The ASP.NET scheme name for a transport is <c>"ApiKey:" + transport</c> — see
/// <see cref="ApiKeySchemes"/>. New customer integrations that use a non-standard header use
/// the custom-header escape hatch rather than extending this set ad hoc; genuinely common new
/// transports are promoted into this class in a future version.
/// </para>
/// </remarks>
public static class ApiKeyTransports {

	/// <summary>
	/// The <c>Authorization: Bearer &lt;token&gt;</c> transport — an opaque (non-JWT) API key
	/// presented as a bearer token. Distinguished from JWT bearer schemes by token prefix.
	/// </summary>
	public const string Bearer = "Bearer";

	/// <summary>The <c>X-Api-Key</c> header transport — the most common custom-header convention.</summary>
	public const string XApiKey = "X-Api-Key";

	/// <summary>The <c>Ocp-Apim-Subscription-Key</c> header transport — Azure API Management's subscription-key header.</summary>
	public const string OcpApimSubscriptionKey = "Ocp-Apim-Subscription-Key";

	/// <summary>The <c>X-Auth-Token</c> header transport — a common alternative custom-header convention.</summary>
	public const string XAuthToken = "X-Auth-Token";

}
