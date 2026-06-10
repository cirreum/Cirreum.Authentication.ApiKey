namespace Cirreum.Authentication.Configuration;

using Cirreum.AuthenticationProvider;
using Cirreum.AuthenticationProvider.Configuration;
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

	/// <summary>
	/// Gets or sets the optional time this credential was created. Required to enforce <see cref="MaxKeyAge"/>
	/// (the NIST SP 800-57 cryptoperiod) for this configured (Form-1) key.
	/// </summary>
	public DateTimeOffset? CreatedAt { get; set; }

	/// <summary>
	/// Gets or sets the optional expiration time for this configured (Form-1) key. Enforced at the handler
	/// chokepoint exactly like a dynamic key's expiry — so the provider-level <c>RequireExpiry</c> knob and an
	/// explicit expiry now apply to configured keys (previously they were silently inert for Form-1).
	/// </summary>
	public DateTimeOffset? ExpiresAt { get; set; }

	/// <summary>
	/// Gets or sets the optional per-credential maximum age (cryptoperiod) for this configured key; may only
	/// <em>tighten</em> the provider-level <c>MaxKeyAge</c>. Enforced against <see cref="CreatedAt"/>.
	/// </summary>
	public TimeSpan? MaxKeyAge { get; set; }

}
