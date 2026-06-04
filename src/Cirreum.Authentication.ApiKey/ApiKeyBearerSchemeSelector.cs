namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Http;

/// <summary>
/// <see cref="IBearerSchemeSelector"/> implementation that routes
/// <c>Authorization: Bearer</c> requests to the ApiKey Bearer scheme
/// (<c>ApiKey:Bearer</c>) when the inbound token matches the configured
/// <see cref="BearerPrefix"/>, or — when no prefix is configured — when the
/// token is non-empty and not JWT-shaped.
/// </summary>
/// <remarks>
/// <para>
/// Registered at
/// <see cref="SchemeSelectorPriority.Key"/>. The selector is a cheap probe; actual
/// credential validation happens in <see cref="ApiKeyAuthenticationHandler"/>.
/// </para>
/// <para>
/// When <see cref="BearerPrefix"/> is set, JWT-shape is irrelevant — the prefix
/// has already committed dispatch. When the prefix is not set, JWT-shaped values
/// are left for the framework's audience-routing selector to claim.
/// </para>
/// </remarks>
public sealed class ApiKeyBearerSchemeSelector(
	string schemeName,
	string? bearerPrefix
) : IBearerSchemeSelector {

	private const string BearerPrefixToken = "Bearer ";

	/// <inheritdoc/>
	public int Priority => SchemeSelectorPriority.Key;

	/// <inheritdoc/>
	public string? BearerPrefix { get; } = bearerPrefix;

	/// <inheritdoc/>
	public (bool Matches, string? SchemeName) TrySelect(HttpContext context) {

		if (context is null) {
			return (false, null);
		}

		var auth = context.Request.Headers.Authorization.FirstOrDefault();
		if (string.IsNullOrWhiteSpace(auth)
			|| !auth.StartsWith(BearerPrefixToken, StringComparison.OrdinalIgnoreCase)) {
			return (false, null);
		}

		var token = auth[BearerPrefixToken.Length..].Trim();
		if (string.IsNullOrEmpty(token)) {
			return (false, null);
		}

		if (!string.IsNullOrEmpty(this.BearerPrefix)) {
			return token.StartsWith(this.BearerPrefix, StringComparison.Ordinal)
				? (true, schemeName)
				: (false, null);
		}

		// Prefix-less fallback: claim opaque (non-JWT) Bearer values.
		return IsJwtShape(token) ? (false, null) : (true, schemeName);
	}

	private static bool IsJwtShape(string value) {
		var firstDot = value.IndexOf('.');
		if (firstDot <= 0 || firstDot == value.Length - 1) {
			return false;
		}
		var secondDot = value.IndexOf('.', firstDot + 1);
		return secondDot > firstDot && secondDot < value.Length - 1
			&& value.IndexOf('.', secondDot + 1) == -1;
	}

}
