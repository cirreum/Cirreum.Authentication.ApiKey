namespace Cirreum.Authentication.Configuration;

using Cirreum.Authentication.ApiKey;
using Cirreum.AuthenticationProvider;
using Cirreum.AuthenticationProvider.Configuration;
/// <summary>
/// Configuration settings for the ApiKey authentication provider — a collection of
/// per-client instances plus per-provider options. Bound once from
/// <c>Cirreum:Authentication:Providers:ApiKey</c>; the <see cref="Validation"/> and
/// <see cref="Revocation"/> sub-objects bind from the matching sub-sections.
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

	/// <summary>
	/// Validation knobs (the two-forms strength floor + <c>AllowWeakConfiguredKeys</c> for Form-1
	/// configured keys; the stored-hash algorithm for Form-2 managed keys). Binds from the
	/// <c>Validation</c> sub-section; defaults apply when absent.
	/// </summary>
	public ApiKeyValidationOptions Validation { get; set; } = new();

	/// <summary>
	/// Revocation knobs (<c>AllowFaultedDenylist</c>, <c>MaxDenylistEntries</c>). Binds from the
	/// <c>Revocation</c> sub-section; defaults apply when absent.
	/// </summary>
	public ApiKeyRevocationOptions Revocation { get; set; } = new();

}

