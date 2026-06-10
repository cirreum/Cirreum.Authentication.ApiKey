namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;
/// <summary>
/// An authenticated ApiKey client — the canonical record returned by
/// <see cref="IApiKeyClientResolver"/> when a presented credential matches a
/// registered entry. Carries the identity claims, role assignments, and transport
/// metadata used by the scheme handler to construct the <c>ClaimsPrincipal</c>.
/// </summary>
/// <remarks>
/// The ASP.NET authentication scheme name (e.g. <c>ApiKey:Bearer</c>,
/// <c>ApiKey:X-Api-Key</c>) is carried by the resulting
/// <see cref="Microsoft.AspNetCore.Authentication.AuthenticationTicket.AuthenticationScheme"/>;
/// the client model is per-credential identity metadata, not per-scheme. Multi-scheme model.
/// </remarks>
public sealed record ApiKeyClient {

	/// <summary>
	/// Gets the unique identifier for this client.
	/// </summary>
	public required string ClientId { get; init; }

	/// <summary>
	/// Gets the display name for this client.
	/// </summary>
	public required string ClientName { get; init; }

	/// <summary>
	/// Gets the roles assigned to this client.
	/// </summary>
	public IReadOnlyList<string> Roles { get; init; } = [];

	/// <summary>
	/// Gets the transports this client's credential is accepted from. Used as a
	/// validity filter at handler lookup time: when the handler resolves a client,
	/// it verifies the resolved client's <see cref="AcceptedTransports"/> includes
	/// the transport the credential actually arrived on; rejects otherwise.
	/// Default is <see cref="CredentialTransport.BearerAuthorizationHeader"/>.
	/// </summary>
	public CredentialTransport AcceptedTransports { get; init; } = CredentialTransport.BearerAuthorizationHeader;

	/// <summary>
	/// Gets the optional expiration time for this client's API key. Enforced at the handler chokepoint
	/// (every credential, regardless of which resolver ran) — see <see cref="ApiKeyAuthenticationHandler"/>.
	/// </summary>
	public DateTimeOffset? ExpiresAt { get; init; }

	/// <summary>
	/// Gets the time this credential was created. Required to enforce <see cref="MaxKeyAge"/>
	/// (the NIST SP 800-57 cryptoperiod) at the handler chokepoint.
	/// </summary>
	public DateTimeOffset? CreatedAt { get; init; }

	/// <summary>
	/// Gets an optional per-credential maximum age (cryptoperiod). Enforced against <see cref="CreatedAt"/>
	/// at the handler chokepoint; may only <em>tighten</em> the configured provider cap.
	/// </summary>
	public TimeSpan? MaxKeyAge { get; init; }

	/// <summary>
	/// Gets optional custom claims to include in the client's identity.
	/// </summary>
	public IReadOnlyDictionary<string, string>? Claims { get; init; }

	/// <summary>
	/// Gets the scopes granted to this client's credential, surfaced as <c>scope</c> claims on the
	/// authenticated identity (ADR-0020 §9 per-key overrides).
	/// </summary>
	public IReadOnlyList<string> Scopes { get; init; } = [];

}
