namespace Cirreum.Authentication;

using Cirreum.Authentication.ApiKey;

/// <summary>
/// Composition options for <c>AddApiKey(...)</c>. Declares which transports the ApiKey
/// provider accepts and, optionally, dynamic API key <em>sources</em> — a backing store of keys read
/// at request time by an <see cref="IApiKeyClientResolver"/> you supply.
/// </summary>
/// <remarks>
/// <para>
/// Transports — which header (or Bearer scheme) carries the key:
/// </para>
/// <list type="bullet">
///   <item><b>Default:</b> no <see cref="AcceptTransports"/> call — all well-known
///   <see cref="ApiKeyTransport"/> values are accepted (<c>Bearer</c>, <c>X-Api-Key</c>,
///   <c>Ocp-Apim-Subscription-Key</c>, <c>X-Auth-Token</c>).</item>
///   <item><b>Restrict:</b> <see cref="AcceptTransports"/> accepts only the listed well-known
///   transports; called with no arguments it clears them all.</item>
///   <item><b>Add custom:</b> <see cref="AddCustomTransport"/> additively accepts a non-standard
///   header, on top of whatever well-known set is active.</item>
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

	private static readonly ApiKeyTransport[] AllWellKnownTransports = Enum.GetValues<ApiKeyTransport>();

	private readonly List<ApiKeyTransport> _acceptedTransports = [];
	private readonly List<string> _customHeaders = [];
	private readonly List<ApiKeyNamedSourceRegistration> _namedSources = [];
	private bool _transportsRestricted;

	/// <summary>
	/// Restricts the provider to a subset of the well-known transports (<see cref="ApiKeyTransport"/>).
	/// <b>Not required</b> — omit it entirely and all well-known transports are accepted. Calling it (even
	/// with an empty array) opts out of that default and registers <b>only</b> the transports you list,
	/// so <c>AcceptTransports()</c> with no arguments <b>clears</b> the well-known set (accept none of
	/// them — typically paired with <see cref="AddCustomTransport"/> to accept only a non-standard header).
	/// Custom headers added via <see cref="AddCustomTransport"/> are unaffected — they are always accepted.
	/// </summary>
	/// <param name="transports">The well-known transports to accept; empty clears the default set.</param>
	/// <returns>This options instance for chaining.</returns>
	public ApiKeyOptions AcceptTransports(params ApiKeyTransport[] transports) {
		ArgumentNullException.ThrowIfNull(transports);
		this._transportsRestricted = true;
		foreach (var transport in transports) {
			if (!this._acceptedTransports.Contains(transport)) {
				this._acceptedTransports.Add(transport);
			}
		}
		return this;
	}

	/// <summary>
	/// Additively accepts a custom (non-standard) header transport — registered <b>on top of</b> whatever
	/// well-known set is active (the all-well-known default, or the subset from <see cref="AcceptTransports"/>).
	/// It never restricts the well-known transports. Use for partner- or customer-mandated headers that are
	/// not among the well-known <see cref="ApiKeyTransport"/> values (e.g. <c>X-Partner-ApiKey</c>).
	/// </summary>
	/// <param name="headerName">The HTTP header carrying the API key (e.g. <c>X-Partner-ApiKey</c>).</param>
	/// <returns>This options instance for chaining.</returns>
	public ApiKeyOptions AddCustomTransport(string headerName) {
		ArgumentException.ThrowIfNullOrWhiteSpace(headerName);
		if (!this._customHeaders.Contains(headerName, StringComparer.OrdinalIgnoreCase)) {
			this._customHeaders.Add(headerName);
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

	/// <summary>
	/// The resolved set of well-known transports the provider accepts: all of them by default, the
	/// <see cref="AcceptTransports"/> subset once restricted, or none after a clearing
	/// <c>AcceptTransports()</c> call. Custom headers (<see cref="CustomHeaders"/>) are additive on top.
	/// </summary>
	internal IReadOnlyList<ApiKeyTransport> AcceptedTransports =>
		this._transportsRestricted ? this._acceptedTransports : AllWellKnownTransports;

	/// <summary>
	/// Custom header transports added via <see cref="AddCustomTransport"/> — always accepted, additively.
	/// </summary>
	internal IReadOnlyList<string> CustomHeaders => this._customHeaders;

	/// <summary>
	/// The default dynamic source, or <see langword="null"/> when none was registered.
	/// </summary>
	internal ApiKeyDefaultSourceRegistration? DefaultSource { get; private set; }

	/// <summary>
	/// The named dynamic sources declared via <see cref="AddNamedSource{TResolver}"/>.
	/// </summary>
	internal IReadOnlyList<ApiKeyNamedSourceRegistration> NamedSources => this._namedSources;

}
