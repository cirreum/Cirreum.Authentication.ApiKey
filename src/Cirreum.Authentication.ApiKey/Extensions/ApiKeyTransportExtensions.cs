namespace Cirreum.Authentication;

/// <summary>
/// Resolves the HTTP header name an <see cref="ApiKeyTransport"/> carries its key on.
/// </summary>
/// <remarks>
/// The enum names a transport; this names the header. It serves both directions — the framework
/// registers one scheme per transport with it, and a calling application uses it to set the header
/// on an outbound request instead of hardcoding the literal:
/// <code>
/// request.Headers.Add(ApiKeyTransport.XApiKey.HeaderName(), apiKey);
/// </code>
/// </remarks>
public static class ApiKeyTransportExtensions {

	/// <summary>
	/// Gets the HTTP header name that carries the key for a header-based transport.
	/// </summary>
	/// <param name="transport">The transport to resolve. Must be header-based —
	/// <see cref="ApiKeyTransport.Bearer"/> is not.</param>
	/// <returns>The header name — <c>X-Api-Key</c> for <see cref="ApiKeyTransport.XApiKey"/>, and so on.</returns>
	/// <exception cref="ArgumentOutOfRangeException">
	/// <paramref name="transport"/> is <see cref="ApiKeyTransport.Bearer"/>, which carries its key in the
	/// standard <c>Authorization</c> header rather than a custom one. A caller presenting a key that way sets
	/// <c>Authorization: Bearer &lt;key&gt;</c> directly; the framework registers it through its own Bearer path.
	/// </exception>
	public static string HeaderName(this ApiKeyTransport transport) => transport switch {
		ApiKeyTransport.XApiKey => ApiKeyTransports.XApiKey,
		ApiKeyTransport.OcpApimSubscriptionKey => ApiKeyTransports.OcpApimSubscriptionKey,
		ApiKeyTransport.XAuthToken => ApiKeyTransports.XAuthToken,
		_ => throw new ArgumentOutOfRangeException(
			nameof(transport), transport,
			"Bearer carries its key in the standard Authorization header, not a custom one."),
	};

}
