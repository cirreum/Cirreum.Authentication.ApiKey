namespace Cirreum.Authentication.Configuration;

using Cirreum.AuthenticationProvider.Configuration;
using Cirreum.AuthenticationProvider;
/// <summary>
/// Configuration settings for the ApiKey authentication provider — a collection of
/// per-client instances plus per-provider options.
/// </summary>
public class ApiKeyAuthenticationSettings
	: AuthenticationProviderSettings<ApiKeyAuthenticationInstanceSettings> {

	/// <summary>
	/// Optional Bearer-token prefix shared by every instance of this provider that
	/// accepts the <see cref="CredentialTransport.BearerAuthorizationHeader"/>
	/// transport. When set, the framework-recommended shape is
	/// <c>{scheme}_{env}_{raw}</c> (for example, <c>ak_prod_</c>). The Bearer
	/// scheme selector strips the prefix before passing the token to the handler.
	/// </summary>
	/// <remarks>
	/// When this is <see langword="null"/>
	/// the ApiKey Bearer selector falls back to JWT-shape disambiguation (claims
	/// only when the Bearer value is not JWT-shaped). Boot-time validation in the
	/// umbrella package enforces cross-provider prefix uniqueness when multiple
	/// Bearer-probing providers are registered.
	/// </remarks>
	public string? BearerPrefix { get; set; }

}

