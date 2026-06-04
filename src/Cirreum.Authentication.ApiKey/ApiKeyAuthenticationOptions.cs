namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Authentication;

/// <summary>
/// Options for the ApiKey authentication handler. Configured per ASP.NET scheme — one
/// scheme per <c>(Provider, Transport)</c> tuple.
/// The handler reads from one source determined by these options; there is no
/// multi-transport branching at request time.
/// </summary>
public class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions {

	/// <summary>
	/// The single transport this handler reads from. Either
	/// <see cref="CredentialTransport.BearerAuthorizationHeader"/> or
	/// <see cref="CredentialTransport.CustomHeader"/>.
	/// </summary>
	public CredentialTransport Transport { get; set; } = CredentialTransport.BearerAuthorizationHeader;

	/// <summary>
	/// When <see cref="Transport"/> is <see cref="CredentialTransport.CustomHeader"/>,
	/// the configured header name (e.g. <c>X-Api-Key</c>). Ignored when
	/// <see cref="Transport"/> is Bearer.
	/// </summary>
	public string HeaderName { get; set; } = "X-Api-Key";

	/// <summary>
	/// When <see cref="Transport"/> is Bearer and the provider has a configured
	/// <c>BearerPrefix</c>, the handler strips this prefix from the inbound token
	/// before passing it to the resolver. The Bearer selector already validated
	/// the prefix at probe time; this is just for consistency. <see langword="null"/>
	/// when no prefix is configured.
	/// </summary>
	public string? BearerPrefix { get; set; }

}
