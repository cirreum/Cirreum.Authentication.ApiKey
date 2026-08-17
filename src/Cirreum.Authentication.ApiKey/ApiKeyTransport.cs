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
