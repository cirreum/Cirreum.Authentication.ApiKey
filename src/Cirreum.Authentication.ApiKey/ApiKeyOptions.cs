namespace Cirreum.Authentication;

using Cirreum.Authentication.ApiKey;

/// <summary>
/// Composition options for <c>AddApiKey(...)</c>. Declares which transports the ApiKey
/// provider accepts and, optionally, a dynamic <see cref="IApiKeyClientResolver"/> that
/// validates credentials at request time against an app store.
/// </summary>
/// <remarks>
/// <para>
/// Three composition modes:
/// </para>
/// <list type="bullet">
///   <item><b>Mode A (default):</b> no <c>AddTransport</c> / <c>AddCustomHeaderTransport</c>
///   calls — all well-known transports are registered (<see cref="ApiKeyTransports.Bearer"/>,
///   <see cref="ApiKeyTransports.XApiKey"/>, <see cref="ApiKeyTransports.OcpApimSubscriptionKey"/>,
///   <see cref="ApiKeyTransports.XAuthToken"/>). Future-proof against new customer
///   integrations without a recompile.</item>
///   <item><b>Mode B:</b> one or more <see cref="AddTransport"/> calls — only the named
///   transports are registered (restriction discipline).</item>
///   <item><b>Mode C:</b> one or more <see cref="AddCustomHeaderTransport"/> calls — a
///   non-standard header escape hatch.</item>
/// </list>
/// <para>
/// Modes B and C combine; declaring any transport explicitly opts out of the
/// well-known default. A transport with no validation source behind it (no configured
/// instance, no dynamic resolver covering it) is an orphan: it registers and returns
/// 401, and the boot-time auth-posture analyzer flags it.
/// </para>
/// </remarks>
public sealed class ApiKeyOptions {

	private readonly List<string> _transports = [];
	private readonly List<string> _customHeaders = [];

	/// <summary>
	/// Adds a well-known transport (a value from <see cref="ApiKeyTransports"/>). Opts the
	/// provider out of the all-well-known default — only explicitly added transports register.
	/// </summary>
	/// <param name="transport">The transport — <see cref="ApiKeyTransports.Bearer"/> registers
	/// the <c>ApiKey:Bearer</c> scheme; any other value is treated as a header name and
	/// registers an <c>ApiKey:{header}</c> scheme.</param>
	/// <returns>This options instance for chaining.</returns>
	public ApiKeyOptions AddTransport(string transport) {
		ArgumentException.ThrowIfNullOrWhiteSpace(transport);
		if (!_transports.Contains(transport, StringComparer.OrdinalIgnoreCase)) {
			_transports.Add(transport);
		}
		return this;
	}

	/// <summary>
	/// Adds a custom (non-standard) header transport. Opts the provider out of the
	/// all-well-known default. Use for partner- or customer-mandated headers that are
	/// not in <see cref="ApiKeyTransports"/>.
	/// </summary>
	/// <param name="headerName">The HTTP header carrying the API key (e.g. <c>X-Partner-ApiKey</c>).</param>
	/// <returns>This options instance for chaining.</returns>
	public ApiKeyOptions AddCustomHeaderTransport(string headerName) {
		ArgumentException.ThrowIfNullOrWhiteSpace(headerName);
		if (!_customHeaders.Contains(headerName, StringComparer.OrdinalIgnoreCase)) {
			_customHeaders.Add(headerName);
		}
		return this;
	}

	/// <summary>
	/// Registers a dynamic <see cref="IApiKeyClientResolver"/> that validates presented
	/// credentials at request time, typically against a database or external store. When
	/// configured instances also exist, the dynamic resolver is composed after the
	/// configuration-backed resolver (configured keys win, then the dynamic store).
	/// </summary>
	/// <typeparam name="TResolver">The app's resolver implementation.</typeparam>
	/// <param name="caching">Optional caching configuration. When supplied, the resolver
	/// is wrapped in a <see cref="CachingApiKeyClientResolver"/> with these options;
	/// when <see langword="null"/>, no caching layer is added.</param>
	/// <returns>This options instance for chaining.</returns>
	public ApiKeyOptions AddResolver<TResolver>(Action<ApiKeyCachingOptions>? caching = null)
		where TResolver : class, IApiKeyClientResolver {
		this.DynamicResolverType = typeof(TResolver);
		this.CachingConfigure = caching;
		return this;
	}

	/// <summary>True when the app declared any transport explicitly (modes B/C); false
	/// selects the all-well-known default (mode A).</summary>
	internal bool HasExplicitTransports => _transports.Count > 0 || _customHeaders.Count > 0;

	/// <summary>Explicitly-added well-known transports (empty unless mode B was used).</summary>
	internal IReadOnlyList<string> Transports => _transports;

	/// <summary>Explicitly-added custom header transports (empty unless mode C was used).</summary>
	internal IReadOnlyList<string> CustomHeaders => _customHeaders;

	/// <summary>The dynamic resolver type, or <see langword="null"/> when validation is
	/// configuration-only.</summary>
	internal Type? DynamicResolverType { get; private set; }

	/// <summary>Caching configuration for the dynamic resolver, or <see langword="null"/>
	/// when no caching layer is requested.</summary>
	internal Action<ApiKeyCachingOptions>? CachingConfigure { get; private set; }

}
