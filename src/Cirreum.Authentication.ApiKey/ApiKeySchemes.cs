namespace Cirreum.Authentication;

/// <summary>
/// The ASP.NET authentication scheme names for the ApiKey provider's well-known transports.
/// App authors reference these in policy definitions
/// (<c>.AddAuthenticationSchemes(ApiKeySchemes.Bearer)</c>) and anywhere a scheme name is
/// required. Each value is <c>"ApiKey:" + </c> the corresponding <see cref="ApiKeyTransports"/>
/// value, enforcing the <c>{Provider}:{Transport}</c> scheme-naming convention
/// at the constant-definition site.
/// </summary>
/// <remarks>
/// These are the IntelliSense-discoverable scheme constants; the matching
/// runtime registration is performed by the ApiKey registrar / dynamic-resolver extensions,
/// which produce the identical <c>ApiKey:{header}</c> scheme strings.
/// </remarks>
public static class ApiKeySchemes {

	/// <summary>Scheme name for the <see cref="ApiKeyTransports.Bearer"/> transport — <c>ApiKey:Bearer</c>.</summary>
	public const string Bearer = "ApiKey:" + ApiKeyTransports.Bearer;

	/// <summary>Scheme name for the <see cref="ApiKeyTransports.XApiKey"/> transport — <c>ApiKey:X-Api-Key</c>.</summary>
	public const string XApiKey = "ApiKey:" + ApiKeyTransports.XApiKey;

	/// <summary>Scheme name for the <see cref="ApiKeyTransports.OcpApimSubscriptionKey"/> transport — <c>ApiKey:Ocp-Apim-Subscription-Key</c>.</summary>
	public const string OcpApimSubscriptionKey = "ApiKey:" + ApiKeyTransports.OcpApimSubscriptionKey;

	/// <summary>Scheme name for the <see cref="ApiKeyTransports.XAuthToken"/> transport — <c>ApiKey:X-Auth-Token</c>.</summary>
	public const string XAuthToken = "ApiKey:" + ApiKeyTransports.XAuthToken;

}
