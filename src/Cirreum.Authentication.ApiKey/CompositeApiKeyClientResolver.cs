namespace Cirreum.Authentication.ApiKey;

using Microsoft.Extensions.Logging;

/// <summary>
/// A composite resolver that chains multiple <see cref="IApiKeyClientResolver"/> instances,
/// trying each in order until one succeeds.
/// </summary>
/// <remarks>
/// <para>
/// This is useful when combining configuration-based keys (for internal services)
/// with database-backed keys (for external customers).
/// </para>
/// <para>
/// The first resolver to return a successful result wins. Resolvers are tried
/// in the order they were added.
/// </para>
/// </remarks>
public sealed class CompositeApiKeyClientResolver : IApiKeyClientResolver {

	private readonly List<IApiKeyClientResolver> _resolvers;
	private readonly ILogger<CompositeApiKeyClientResolver> _logger;
	private readonly Lazy<IReadOnlySet<string>> _supportedHeaders;

	/// <summary>
	/// Initializes a new instance of the <see cref="CompositeApiKeyClientResolver"/> class.
	/// </summary>
	/// <param name="resolvers">The resolvers to chain, in priority order.</param>
	/// <param name="logger">The logger.</param>
	public CompositeApiKeyClientResolver(
		IEnumerable<IApiKeyClientResolver> resolvers,
		ILogger<CompositeApiKeyClientResolver> logger) {
		_resolvers = resolvers?.ToList() ?? throw new ArgumentNullException(nameof(resolvers));
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));

		if (_resolvers.Count == 0) {
			throw new ArgumentException("At least one resolver must be provided", nameof(resolvers));
		}

		_supportedHeaders = new Lazy<IReadOnlySet<string>>(() =>
			_resolvers
				.SelectMany(r => r.SupportedHeaders)
				.ToHashSet(StringComparer.OrdinalIgnoreCase));
	}

	/// <inheritdoc/>
	public IReadOnlySet<string> SupportedHeaders => _supportedHeaders.Value;

	/// <inheritdoc/>
	public async Task<ApiKeyResolveResult> ResolveAsync(
		string providedKey,
		ApiKeyLookupContext context,
		CancellationToken cancellationToken = default) {

		var headerName = context.HeaderName;

		for (var i = 0; i < _resolvers.Count; i++) {
			var resolver = _resolvers[i];

			// Skip resolvers that don't handle this header
			if (!resolver.SupportedHeaders.Contains(headerName)) {
				continue;
			}

			// A throwing resolver fails closed to a miss (never a 500); cancellation propagates.
			var result = await ApiKeyResolverGuard.SafeResolveAsync(
				resolver, providedKey, context, _logger, cancellationToken);

			if (result.IsSuccess) {
				if (_logger.IsEnabled(LogLevel.Debug)) {
					_logger.LogDebug(
						"API key resolved by resolver {ResolverIndex} ({ResolverType}) for header {HeaderName}",
						i,
						resolver.GetType().Name,
						headerName);
				}
				return result;
			}

			// NotFound is the only soft outcome — try the next resolver. Every other outcome (Expired,
			// Failed, MissingRoutingSignal) is a definitive answer for this credential: stop and return it.
			// Branch on the typed Outcome, never on the free-text FailureReason.
			if (result.Outcome != ApiKeyResolveOutcome.NotFound) {
				if (_logger.IsEnabled(LogLevel.Debug)) {
					_logger.LogDebug(
						"API key resolution stopped at resolver {ResolverIndex} ({ResolverType}): {Outcome}",
						i,
						resolver.GetType().Name,
						result.Outcome);
				}
				return result;
			}

			// "Not found" - try next resolver
		}

		if (_logger.IsEnabled(LogLevel.Debug)) {
			_logger.LogDebug(
				"API key not found in any resolver for header {HeaderName}",
				headerName);
		}

		return ApiKeyResolveResult.NotFound();
	}
}
