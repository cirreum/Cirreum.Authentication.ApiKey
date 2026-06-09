namespace Cirreum.Authentication;

/// <summary>
/// The literal HTTP header names for the well-known API key transports (for <c>Bearer</c>, the
/// <c>Authorization: Bearer</c> scheme token). Internal: the app-facing surface is the
/// <see cref="ApiKeyTransport"/> enum (for <see cref="ApiKeyOptions.AcceptTransports"/>) and the
/// <see cref="ApiKeySchemes"/> constants (for <c>[Authorize(AuthenticationSchemes = ...)]</c>). These
/// strings back both — the ASP.NET scheme name for a transport is <c>"ApiKey:" + transport</c>.
/// </summary>
internal static class ApiKeyTransports {

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
