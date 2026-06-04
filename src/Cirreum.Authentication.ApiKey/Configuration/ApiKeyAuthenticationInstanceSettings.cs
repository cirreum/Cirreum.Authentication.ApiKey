namespace Cirreum.Authentication.Configuration;

using Cirreum.AuthenticationProvider.Configuration;
using Cirreum.AuthenticationProvider;
/// <summary>
/// Configuration settings for an individual ApiKey authentication scheme instance.
/// </summary>
/// <remarks>
/// Inherits <see cref="HeaderAuthenticationProviderInstanceSettings.HeaderName"/>,
/// <see cref="HeaderAuthenticationProviderInstanceSettings.ClientId"/>,
/// <see cref="HeaderAuthenticationProviderInstanceSettings.ClientName"/>, and
/// <see cref="HeaderAuthenticationProviderInstanceSettings.Roles"/> from the base
/// class. Adds the <see cref="AcceptedTransports"/> property to support
/// <c>Authorization: Bearer</c> transport alongside the legacy custom-header transport.
/// </remarks>
public class ApiKeyAuthenticationInstanceSettings : HeaderAuthenticationProviderInstanceSettings {

	/// <summary>
	/// Gets or sets the transports this credential accepts. Defaults to
	/// <see cref="CredentialTransport.BearerAuthorizationHeader"/> (RFC 6750-aligned,
	/// the new default). Apps with existing partners using a custom
	/// header explicitly set <see cref="CredentialTransport.CustomHeader"/> alongside
	/// the inherited <c>HeaderName</c>.
	/// </summary>
	/// <remarks>
	/// When set to a combination including <see cref="CredentialTransport.CustomHeader"/>,
	/// the inherited <see cref="HeaderAuthenticationProviderInstanceSettings.HeaderName"/>
	/// names the custom header. When only Bearer is accepted, <c>HeaderName</c> is
	/// ignored.
	/// </remarks>
	public CredentialTransport AcceptedTransports { get; set; } = CredentialTransport.BearerAuthorizationHeader;

}
