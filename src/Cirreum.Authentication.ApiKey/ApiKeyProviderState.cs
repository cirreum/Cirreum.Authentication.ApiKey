namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;
/// <summary>
/// Singleton DI service carrying provider-level state for the ApiKey track. Shared
/// across the configured-instances path (<see cref="ApiKeyAuthenticationRegistrar"/>)
/// and the declared-transport path of the <c>AddApiKey(...)</c> verb so an app using
/// either or both produces exactly one ASP.NET scheme per <c>(Provider, Transport)</c>
/// tuple and honors a single configured <see cref="BearerPrefix"/>. Also guards the
/// verb against double composition via <see cref="TryBeginComposition"/>.
/// </summary>
/// <remarks>
/// <para>
/// Lifecycle: the registrar's <c>Register</c> method writes
/// <see cref="BearerPrefix"/> from <c>Cirreum:Authentication:Providers:ApiKey:BearerPrefix</c>
/// before iterating instances; the dynamic-extension path reads it when registering
/// the <c>ApiKey:Bearer</c> scheme. Idempotency for scheme registration is enforced
/// via <see cref="TryClaimScheme"/> — first caller wins, subsequent calls no-op.
/// </para>
/// <para>
/// The state lives on a singleton rather
/// than the registrar instance because the registrar is <c>new</c>-ed once per
/// <c>RegisterAuthenticationProvider</c> call and GC'd after; the dynamic-extension
/// path runs later, after the registrar is gone.
/// </para>
/// </remarks>
internal sealed class ApiKeyProviderState {

	private readonly HashSet<string> _registeredSchemes = new(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// Provider-level Bearer-token prefix from
	/// <c>Cirreum:Authentication:Providers:ApiKey:BearerPrefix</c>. Set by the
	/// registrar during composition; read by both the configured-instance and
	/// dynamic-resolver paths when registering the <c>ApiKey:Bearer</c> scheme so
	/// every code path stamps the same prefix on options + selector.
	/// </summary>
	public string? BearerPrefix { get; set; }

	/// <summary>
	/// Attempts to claim a scheme name for registration. Returns <see langword="true"/>
	/// on first call for a given name; <see langword="false"/> on subsequent calls.
	/// Callers should skip the actual <c>AddScheme</c> + selector registration when
	/// this returns <see langword="false"/>.
	/// </summary>
	public bool TryClaimScheme(string schemeName) => _registeredSchemes.Add(schemeName);

	/// <summary>
	/// Attempts to begin ApiKey composition. Returns <see langword="true"/> on the first
	/// call; <see langword="false"/> thereafter. Guards <c>AddApiKey(...)</c> against
	/// being called more than once per host.
	/// </summary>
	public bool TryBeginComposition() {
		if (_composed) {
			return false;
		}
		_composed = true;
		return true;
	}

	private bool _composed;

}
