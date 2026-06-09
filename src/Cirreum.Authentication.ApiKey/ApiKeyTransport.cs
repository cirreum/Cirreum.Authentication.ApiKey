namespace Cirreum.Authentication;

/// <summary>
/// A well-known credential transport the ApiKey provider can accept — the header (or the
/// <c>Authorization: Bearer</c> scheme) a key is presented on. Use
/// <see cref="ApiKeyOptions.AcceptTransports"/> to restrict the provider to a subset of these; a
/// non-standard header is added additively via <see cref="ApiKeyOptions.AddCustomTransport"/>.
/// </summary>
public enum ApiKeyTransport {

	/// <summary>
	/// The <c>Authorization: Bearer &lt;key&gt;</c> transport — an opaque (non-JWT) API key presented as
	/// a bearer token, distinguished from JWT bearer schemes by token prefix / shape.
	/// </summary>
	Bearer,

	/// <summary>The <c>X-Api-Key</c> header — the most common custom-header convention.</summary>
	XApiKey,

	/// <summary>The <c>Ocp-Apim-Subscription-Key</c> header — Azure API Management's subscription-key header.</summary>
	OcpApimSubscriptionKey,

	/// <summary>The <c>X-Auth-Token</c> header — a common alternative custom-header convention.</summary>
	XAuthToken,
}

/// <summary>Maps an <see cref="ApiKeyTransport"/> to its HTTP header name for scheme registration.</summary>
internal static class ApiKeyTransportExtensions {

	/// <summary>
	/// The HTTP header name carrying the key for a header-based transport. <see cref="ApiKeyTransport.Bearer"/>
	/// has no custom header (it uses <c>Authorization</c>) and must be registered via the Bearer path instead.
	/// </summary>
	public static string HeaderName(this ApiKeyTransport transport) => transport switch {
		ApiKeyTransport.XApiKey => ApiKeyTransports.XApiKey,
		ApiKeyTransport.OcpApimSubscriptionKey => ApiKeyTransports.OcpApimSubscriptionKey,
		ApiKeyTransport.XAuthToken => ApiKeyTransports.XAuthToken,
		_ => throw new ArgumentOutOfRangeException(
			nameof(transport), transport, "Bearer has no custom header name; register it via the Bearer path."),
	};
}
