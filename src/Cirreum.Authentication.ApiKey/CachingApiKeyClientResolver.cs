namespace Cirreum.Authentication.ApiKey;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// A caching decorator for <see cref="IApiKeyClientResolver"/> that provides
/// in-memory caching of resolution results to reduce database/external lookups.
/// </summary>
/// <remarks>
/// <para>
/// This resolver caches by a hash of the provided key (never the raw key) to
/// maintain security while enabling efficient lookups.
/// </para>
/// <para>
/// For multi-node deployments, the cache TTL ensures eventual consistency.
/// If stronger consistency is required, consider implementing a distributed
/// cache resolver or using shorter TTLs.
/// </para>
/// </remarks>
/// <remarks>
/// Initializes a new instance of the <see cref="CachingApiKeyClientResolver"/> class.
/// </remarks>
/// <param name="inner">The inner resolver to cache.</param>
/// <param name="cache">The memory cache instance.</param>
/// <param name="options">The caching options.</param>
/// <param name="logger">The logger.</param>
public sealed class CachingApiKeyClientResolver(
	IApiKeyClientResolver inner,
	IMemoryCache cache,
	IOptions<ApiKeyCachingOptions> options,
	ILogger<CachingApiKeyClientResolver> logger
) : IApiKeyClientResolver, IDisposable {

	private readonly IApiKeyClientResolver _inner = inner ?? throw new ArgumentNullException(nameof(inner));
	private readonly IMemoryCache _cache = cache ?? throw new ArgumentNullException(nameof(cache));
	private readonly ApiKeyCachingOptions _options = options?.Value ?? new ApiKeyCachingOptions();
	private readonly ILogger<CachingApiKeyClientResolver> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
	private readonly bool _ownsCache = false;

	private const string CacheKeyPrefix = "ApiKeyResolver:";
	private const string NotFoundMarker = "__NOT_FOUND__";

	/// <summary>
	/// Initializes a new instance with a dedicated cache.
	/// </summary>
	/// <param name="inner">The inner resolver to cache.</param>
	/// <param name="options">The caching options.</param>
	/// <param name="logger">The logger.</param>
	public CachingApiKeyClientResolver(
		IApiKeyClientResolver inner,
		IOptions<ApiKeyCachingOptions> options,
		ILogger<CachingApiKeyClientResolver> logger)
		: this(
			inner,
			new MemoryCache(new MemoryCacheOptions { SizeLimit = options?.Value?.MaxCacheEntries ?? 10_000 }),
			options ?? Options.Create(new ApiKeyCachingOptions()),
			logger) {
		_ownsCache = true;
	}

	/// <inheritdoc/>
	public IReadOnlySet<string> SupportedHeaders => _inner.SupportedHeaders;

	/// <inheritdoc/>
	public async Task<ApiKeyResolveResult> ResolveAsync(
		string providedKey,
		ApiKeyLookupContext context,
		CancellationToken cancellationToken = default) {

		var headerName = context.HeaderName;
		var cacheKey = GenerateCacheKey(context.RequestedSource, headerName, providedKey);

		// Try to get from cache
		if (_cache.TryGetValue(cacheKey, out var cached)) {
			if (cached is ApiKeyClient client) {
				if (_logger.IsEnabled(LogLevel.Debug)) {
					_logger.LogDebug(
						"API key cache hit for header {HeaderName}: ClientId={ClientId}",
						headerName,
						client.ClientId);
				}
				return ApiKeyResolveResult.Success(client);
			}

			if (cached is string marker && marker == NotFoundMarker) {
				if (_logger.IsEnabled(LogLevel.Debug)) {
					_logger.LogDebug(
						"API key cache hit (negative) for header {HeaderName}",
						headerName);
				}
				return ApiKeyResolveResult.NotFound();
			}
		}

		// Cache miss - resolve from inner
		var result = await _inner.ResolveAsync(providedKey, context, cancellationToken);

		// Cache the result
		if (result.IsSuccess && result.Client is not null) {
			var entryOptions = new MemoryCacheEntryOptions()
				.SetAbsoluteExpiration(_options.SuccessCacheDuration)
				.SetSize(1);

			_cache.Set(cacheKey, result.Client, entryOptions);

			if (_logger.IsEnabled(LogLevel.Debug)) {
				_logger.LogDebug(
					"API key cached for header {HeaderName}: ClientId={ClientId}, Duration={Duration}",
					headerName,
					result.Client.ClientId,
					_options.SuccessCacheDuration);
			}
		} else if (!result.IsSuccess && _options.EnableNegativeCaching) {
			var entryOptions = new MemoryCacheEntryOptions()
				.SetAbsoluteExpiration(_options.NotFoundCacheDuration)
				.SetSize(1);

			_cache.Set(cacheKey, NotFoundMarker, entryOptions);

			if (_logger.IsEnabled(LogLevel.Debug)) {
				_logger.LogDebug(
					"API key negative cached for header {HeaderName}, Duration={Duration}",
					headerName,
					_options.NotFoundCacheDuration);
			}
		}

		return result;
	}

	/// <summary>
	/// Generates a cache key from the routing dimension (<c>X-Api-Source</c>-derived store ref), the
	/// header name, and the provided key. Uses a SHA256 hash to avoid storing raw keys in cache.
	/// </summary>
	/// <remarks>
	/// The <paramref name="requestedSource"/> is part of the lookup identity: the same key resolves to a
	/// different client (or to a miss) depending on which store it is routed to, so a result cached
	/// under one routing dimension must never satisfy a lookup under another — otherwise a negative
	/// (miss) entry from store A could wrongly reject a key that is valid in store B.
	/// </remarks>
	private static string GenerateCacheKey(string? requestedSource, string headerName, string providedKey) {
		// Length-prefix each segment so distinct (source, header) tuples can never collide via a
		// delimiter that also appears inside a value.
		var combined = $"{requestedSource?.Length ?? -1}:{requestedSource}:{headerName.Length}:{headerName}:{providedKey}";
		var bytes = Encoding.UTF8.GetBytes(combined);
		var hash = SHA256.HashData(bytes);
		return $"{CacheKeyPrefix}{Convert.ToBase64String(hash)}";
	}

	/// <inheritdoc/>
	public void Dispose() {
		if (_ownsCache && _cache is IDisposable disposable) {
			disposable.Dispose();
		}
	}
}
