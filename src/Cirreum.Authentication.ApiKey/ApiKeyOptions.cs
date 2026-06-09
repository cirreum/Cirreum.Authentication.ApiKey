namespace Cirreum.Authentication;

using Cirreum.Authentication.ApiKey;

/// <summary>
/// Composition options for <c>AddApiKey(...)</c>. Declares which transports the ApiKey
/// provider accepts and, optionally, dynamic API key <em>sources</em> — a backing store of keys read
/// at request time by an <see cref="IApiKeyClientResolver"/> you supply.
/// </summary>
/// <remarks>
/// <para>
/// Transports — three composition modes:
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
/// Sources — keys come from one of three places, tried in this precedence when no source is addressed:
/// statically <b>configured</b> keys (appsettings / Key Vault instances, wired automatically); the
/// <b>default</b> dynamic source (<see cref="AddDefaultSource{TResolver}"/>, reachable without
/// <c>X-Api-Source</c>); and <b>named</b> dynamic sources (<see cref="AddNamedSource{TResolver}"/>,
/// reached only via an explicit <c>X-Api-Source</c> reference). A transport with no source behind it is
/// an orphan: it registers and returns 401, and the boot-time auth-posture analyzer flags it.
/// </para>
/// </remarks>
public sealed class ApiKeyOptions {

	private readonly List<string> _transports = [];
	private readonly List<string> _customHeaders = [];
	private readonly List<ApiKeyNamedSourceRegistration> _namedSources = [];

	/// <summary>
	/// Adds a well-known transport (a value from <see cref="ApiKeyTransports"/>). This is a
	/// <b>restriction, not an addition</b>: the first call opts the provider out of the all-well-known
	/// default, so from then on <b>only</b> the transports you explicitly add are registered — narrowing
	/// what the whole provider accepts across every source and client. Omit it entirely (the default) to
	/// keep all well-known transports open; to keep them <em>and</em> add a custom one, list them all
	/// explicitly plus <see cref="AddCustomHeaderTransport"/>.
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
	/// Registers the <b>default</b> dynamic API key source — the single source reached when no
	/// <c>X-Api-Source</c> is supplied (the common single-store case). At most one default source may be
	/// registered. Keys are validated at request time by <typeparamref name="TResolver"/>, typically
	/// against a database or external store.
	/// </summary>
	/// <typeparam name="TResolver">The app's resolver implementation for the default source.</typeparam>
	/// <param name="requireClientId">When <see langword="true"/> (the default), the dispatcher rejects a
	/// request that would fall to this source with no <c>X-Client-Id</c> as a non-descript <c>400</c>
	/// before invoking the resolver — guaranteeing an O(1) indexed lookup rather than a scan over every
	/// client's key. Set <see langword="false"/> only when the key is self-identifying or the store is
	/// tiny.</param>
	/// <param name="caching">Optional caching configuration. When supplied, the resolver is wrapped in a
	/// <see cref="CachingApiKeyClientResolver"/>; when <see langword="null"/>, no caching layer is added.</param>
	/// <returns>This options instance for chaining.</returns>
	/// <remarks>
	/// The resolver is a singleton — depend only on singleton-safe services (inject
	/// <c>IServiceScopeFactory</c> / <c>IDbContextFactory</c> for scoped data access).
	/// </remarks>
	public ApiKeyOptions AddDefaultSource<TResolver>(
		bool requireClientId = true,
		Action<ApiKeySourceCachingOptions>? caching = null)
		where TResolver : class, IApiKeyClientResolver {

		if (this.DefaultSource is not null) {
			throw new InvalidOperationException(
				"A default API key source is already registered. Call AddDefaultSource(...) at most once; " +
				"use AddNamedSource(name, ...) for additional, addressable sources.");
		}

		this.DefaultSource = new ApiKeyDefaultSourceRegistration(typeof(TResolver), requireClientId, caching);
		return this;
	}

	/// <summary>
	/// Registers a <b>named</b>, addressable dynamic API key source (ADR-0020 §4). Each named source is
	/// reached only via an explicit <c>X-Api-Source</c> reference derived from <paramref name="name"/>,
	/// and is never part of the no-source fallback. Register several side by side (e.g. an internal
	/// source and a partner source). Keys are validated at request time by <typeparamref name="TResolver"/>.
	/// </summary>
	/// <typeparam name="TResolver">The app's resolver implementation for this source.</typeparam>
	/// <param name="name">The code-given source name; the input to the opaque SourceRef derivation. The
	/// name stays in code — clients send the derived ref in <c>X-Api-Source</c>, never the name.</param>
	/// <param name="requireClientId">When <see langword="true"/> (the default), the dispatcher rejects a
	/// request routed to this source with no <c>X-Client-Id</c> as a non-descript <c>400</c> before
	/// invoking the resolver (indexed lookup, not a scan). Set <see langword="false"/> only when the key
	/// is self-identifying or this is a store-per-client source.</param>
	/// <param name="caching">Optional caching configuration; wraps the resolver in a
	/// <see cref="CachingApiKeyClientResolver"/> when supplied.</param>
	/// <returns>This options instance for chaining.</returns>
	/// <remarks>
	/// The resolver is registered as a singleton keyed by the derived SourceRef — depend only on
	/// singleton-safe services. Names must be unique; a duplicate (or a SourceRef collision) fails fast.
	/// </remarks>
	public ApiKeyOptions AddNamedSource<TResolver>(
		string name,
		bool requireClientId = true,
		Action<ApiKeySourceCachingOptions>? caching = null)
		where TResolver : class, IApiKeyClientResolver {

		ArgumentException.ThrowIfNullOrWhiteSpace(name);
		this._namedSources.Add(new ApiKeyNamedSourceRegistration(name, typeof(TResolver), requireClientId, caching));
		return this;
	}

	/// <summary>True when the app declared any transport explicitly (modes B/C); false
	/// selects the all-well-known default (mode A).</summary>
	internal bool HasExplicitTransports => _transports.Count > 0 || _customHeaders.Count > 0;

	/// <summary>Explicitly-added well-known transports (empty unless mode B was used).</summary>
	internal IReadOnlyList<string> Transports => _transports;

	/// <summary>Explicitly-added custom header transports (empty unless mode C was used).</summary>
	internal IReadOnlyList<string> CustomHeaders => _customHeaders;

	/// <summary>The default dynamic source, or <see langword="null"/> when none was registered.</summary>
	internal ApiKeyDefaultSourceRegistration? DefaultSource { get; private set; }

	/// <summary>The named dynamic sources declared via <see cref="AddNamedSource{TResolver}"/>.</summary>
	internal IReadOnlyList<ApiKeyNamedSourceRegistration> NamedSources => this._namedSources;

}
