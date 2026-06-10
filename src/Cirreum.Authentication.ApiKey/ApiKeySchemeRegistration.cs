namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Static helpers used by both the configured-instances registration path
/// (<see cref="ApiKeyAuthenticationRegistrar.AddAuthenticationHandler"/>) and the
/// dynamic-resolver extension path
/// (<c>ApiKeyAuthenticationBuilderExtensions</c>) to register ApiKey ASP.NET
/// schemes idempotently against a shared <see cref="ApiKeyProviderState"/>.
/// </summary>
/// <remarks>
/// One ASP.NET scheme per
/// <c>(Provider, Transport)</c> tuple — Bearer transport produces
/// <c>ApiKey:Bearer</c>; each custom-header name produces
/// <c>ApiKey:{HeaderName}</c>. Multiple configured instances accepting Bearer all
/// share the single <c>ApiKey:Bearer</c> scheme; multiple instances accepting the
/// same custom header all share that header's scheme.
/// </remarks>
internal static class ApiKeySchemeRegistration {

	/// <summary>The shared ASP.NET scheme name for ApiKey Bearer transport.</summary>
	public const string BearerSchemeName = ApiKeySchemes.Bearer;

	/// <summary>
	/// Resolves the singleton <see cref="ApiKeyProviderState"/> from the service
	/// collection, creating and registering it on first call. Used by both
	/// registration paths so the state survives across calls.
	/// </summary>
	public static ApiKeyProviderState GetOrAddState(IServiceCollection services) {
		var descriptor = services.FirstOrDefault(d =>
			d.ServiceType == typeof(ApiKeyProviderState));

		if (descriptor?.ImplementationInstance is ApiKeyProviderState existing) {
			return existing;
		}

		var state = new ApiKeyProviderState();
		services.AddSingleton(state);
		return state;
	}

	/// <summary>
	/// Registers the <c>ApiKey:Bearer</c> ASP.NET scheme + handler + selector if
	/// not already registered. The <see cref="ApiKeyProviderState.BearerPrefix"/>
	/// stashed during composition is threaded into options + selector so prefix
	/// validation at request time uses the configured value.
	/// </summary>
	/// <returns>
	/// <see langword="true"/> when this call performed the registration;
	/// <see langword="false"/> when the scheme was already registered.
	/// </returns>
	public static bool TryRegisterBearer(
		IServiceCollection services,
		AuthenticationBuilder authBuilder) {

		var state = GetOrAddState(services);
		if (!state.TryClaimScheme(BearerSchemeName)) {
			return false;
		}

		var bearerPrefix = state.BearerPrefix;

		authBuilder.AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(
			BearerSchemeName,
			options => {
				options.Transport = CredentialTransport.BearerAuthorizationHeader;
				options.BearerPrefix = bearerPrefix;
			});

		services.AddSingleton(new ApiKeyBearerSchemeSelector(BearerSchemeName, bearerPrefix));
		services.AddSingleton<ISchemeSelector>(sp =>
			sp.GetRequiredService<ApiKeyBearerSchemeSelector>());
		services.AddSingleton<IBearerSchemeSelector>(sp =>
			sp.GetRequiredService<ApiKeyBearerSchemeSelector>());

		return true;
	}

	/// <summary>
	/// Registers an <c>ApiKey:{headerName}</c> ASP.NET scheme + handler + selector
	/// if not already registered for the given header name.
	/// </summary>
	/// <returns>
	/// <see langword="true"/> when this call performed the registration;
	/// <see langword="false"/> when the scheme was already registered.
	/// </returns>
	/// <exception cref="ArgumentException">When <paramref name="headerName"/> is
	/// null, empty, or whitespace.</exception>
	public static bool TryRegisterCustomHeader(
		IServiceCollection services,
		AuthenticationBuilder authBuilder,
		string headerName) {

		if (string.IsNullOrWhiteSpace(headerName)) {
			throw new ArgumentException(
				"ApiKey custom-header scheme requires a non-empty header name.",
				nameof(headerName));
		}

		// An HTTP field-name is an RFC 7230 §3.2.6 token. Reject anything else at startup: a non-token name
		// can never function as a real request header, and it would otherwise flow into the scheme name and
		// the WWW-Authenticate realm and produce a malformed response header (N6).
		if (!IsValidHttpFieldName(headerName)) {
			throw new ArgumentException(
				$"ApiKey custom-header name '{headerName}' is not a valid HTTP field-name (RFC 7230 token: " +
				$"ASCII letters/digits and !#$%&'*+-.^_`|~). Choose a token-valid header name.",
				nameof(headerName));
		}

		var schemeName = $"ApiKey:{headerName}";
		var state = GetOrAddState(services);
		if (!state.TryClaimScheme(schemeName)) {
			return false;
		}

		authBuilder.AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(
			schemeName,
			options => {
				options.Transport = CredentialTransport.CustomHeader;
				options.HeaderName = headerName;
			});

		services.AddSingleton<ISchemeSelector>(_ =>
			new ApiKeyHeaderSchemeSelector(schemeName, headerName));

		return true;
	}

	/// <summary>
	/// Whether <paramref name="name"/> is a valid HTTP field-name — an RFC 7230 §3.2.6 token:
	/// <c>1*tchar</c> where <c>tchar = "!#$%&amp;'*+-.^_`|~" / DIGIT / ALPHA</c>.
	/// </summary>
	private static bool IsValidHttpFieldName(string name) {
		foreach (var c in name) {
			var ok = char.IsAsciiLetterOrDigit(c)
				|| c is '!' or '#' or '$' or '%' or '&' or '\'' or '*'
					or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~';
			if (!ok) {
				return false;
			}
		}

		return true;
	}

}
