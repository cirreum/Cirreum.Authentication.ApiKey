namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;
/// <summary>
/// Internal storage record for a registered ApiKey client and its accepted-transport
/// metadata. <see cref="ApiKeyClientRegistry"/> stores these and validates inbound
/// credentials against the <see cref="Key"/> field using constant-time comparison.
/// </summary>
/// <remarks>
/// A single client may be reachable through multiple ASP.NET authentication schemes
/// (e.g. <c>ApiKey:Bearer</c> AND <c>ApiKey:X-Api-Key</c>) when its
/// <see cref="AcceptedTransports"/> includes more than one transport. The per-scheme
/// handler queries the registry for the transport it owns.
/// </remarks>
/// <param name="HeaderName">The HTTP header name when <see cref="AcceptedTransports"/>
/// includes <see cref="CredentialTransport.CustomHeader"/>; ignored otherwise.</param>
/// <param name="Key">The expected API key value (compared in constant time).</param>
/// <param name="ClientId">The unique client identifier.</param>
/// <param name="ClientName">The display name for this client.</param>
/// <param name="Roles">The roles to assign to authenticated requests.</param>
/// <param name="AcceptedTransports">The transports this credential is accepted from.</param>
public sealed record ApiKeyClientEntry(
	string HeaderName,
	string Key,
	string ClientId,
	string ClientName,
	IReadOnlyList<string> Roles,
	CredentialTransport AcceptedTransports);
