namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Http;

/// <summary>
/// <see cref="ISchemeSelector"/> implementation that routes requests carrying a
/// non-empty value in a configured custom header (e.g. <c>X-Api-Key</c>) to the
/// ApiKey scheme bound to that header name.
/// </summary>
/// <remarks>
/// <para>
/// One selector instance per unique custom-header name. The registrar creates a
/// distinct ASP.NET scheme + selector for each custom header configured by the
/// app's ApiKey instances.
/// </para>
/// <para>
/// Multi-scheme model. Registered at
/// <see cref="SchemeSelectorPriority.Key"/>.
/// </para>
/// </remarks>
public sealed class ApiKeyHeaderSchemeSelector(
	string schemeName,
	string headerName
) : ISchemeSelector {

	/// <inheritdoc/>
	public int Priority => SchemeSelectorPriority.Key;

	/// <inheritdoc/>
	public (bool Matches, string? SchemeName) TrySelect(HttpContext context) {

		if (context is null) {
			return (false, null);
		}

		if (!context.Request.Headers.TryGetValue(headerName, out var values)) {
			return (false, null);
		}

		var value = values.FirstOrDefault();
		return string.IsNullOrWhiteSpace(value) ? (false, null) : (true, schemeName);
	}

}
