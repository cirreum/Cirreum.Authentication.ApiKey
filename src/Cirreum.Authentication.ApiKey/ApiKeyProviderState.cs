namespace Cirreum.Authentication.ApiKey;

using System.Security.Cryptography;
using System.Text;
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

	// Per-host (not process-static) so the same configured key registered to two clients is caught
	// within a host, while parallel hosts in one process (notably integration tests) stay isolated.
	// Maps a salted-free SHA-256 of the key → the ClientId it first registered to.
	private readonly Dictionary<string, string> _processedKeys = new(StringComparer.Ordinal);

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

	/// <summary>
	/// Records a configured (Form-1) key as registered to <paramref name="clientId"/>, failing fast if
	/// the same key was already registered to a different client within this host. Prevents two clients
	/// from silently sharing a credential (which would make the authenticated identity ambiguous). The
	/// raw key is never stored — only a SHA-256 digest, used solely for equality.
	/// </summary>
	/// <exception cref="InvalidOperationException">The same key is already registered to another client.</exception>
	public void RegisterUniqueKey(string apiKey, string instanceKey, string clientId) {
		var keyHash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(apiKey)));

		if (!_processedKeys.TryAdd(keyHash, clientId)) {
			throw new InvalidOperationException(
				$"API key for instance '{instanceKey}' is already registered to client '{_processedKeys[keyHash]}'. " +
				$"Cannot register the same key with multiple clients.");
		}
	}

}
