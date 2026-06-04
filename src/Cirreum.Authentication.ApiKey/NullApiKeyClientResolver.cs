namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Fallback <see cref="IApiKeyClientResolver"/> that resolves nothing. Registered by
/// <c>AddApiKey(...)</c> only when no validation source exists — no configured
/// instances and no dynamic resolver — so the <see cref="ApiKeyAuthenticationHandler"/>
/// can still be constructed and every request to an orphaned ApiKey scheme fails cleanly
/// with a 401 rather than throwing a DI resolution error.
/// </summary>
/// <remarks>
/// A scheme registered with no possible validator is an orphan transport (a transport
/// declared via <c>AddApiKey()</c>'s well-known default or an explicit
/// <c>AddTransport(...)</c> with nothing behind it). Orphan handling
/// is non-fatal: the boot-time auth-posture analyzer in <c>Cirreum.Introspection</c>
/// surfaces the orphan as a likely misconfiguration. This resolver is the runtime
/// counterpart that keeps the orphan path a deterministic 401.
/// </remarks>
public sealed class NullApiKeyClientResolver : IApiKeyClientResolver {

	/// <inheritdoc/>
	public IReadOnlySet<string> SupportedHeaders { get; } =
		new HashSet<string>(StringComparer.OrdinalIgnoreCase);

	/// <inheritdoc/>
	public Task<ApiKeyResolveResult> ResolveAsync(
		string providedKey,
		ApiKeyLookupContext context,
		CancellationToken cancellationToken = default) =>
		Task.FromResult(ApiKeyResolveResult.NotFound());

}
