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
public sealed class CachingApiKeyClientResolver : IApiKeyClientResolver, IDisposable {

	private readonly IApiKeyClientResolver _inner;
	private readonly IMemoryCache _cache;
	private readonly ApiKeySourceCachingOptions _options;
	private readonly ILogger<CachingApiKeyClientResolver> _logger;
	private readonly bool _ownsCache;

	private const string CacheKeyPrefix = "ApiKeyResolver:";
	private const string NotFoundMarker = "__NOT_FOUND__";

	/// <summary>
	/// Initializes a new instance over a caller-supplied <see cref="IMemoryCache"/>. <b>Internal</b>: an
	/// externally-supplied (app-wide shared) cache typically has no <c>SizeLimit</c>, which would make the
	/// per-entry <c>SetSize(1)</c> calls throw and turn every resolution into a 500. The framework always
	/// uses the dedicated, size-bounded cache constructor below instead (N12).
	/// </summary>
	internal CachingApiKeyClientResolver(
		IApiKeyClientResolver inner,
		IMemoryCache cache,
		IOptions<ApiKeySourceCachingOptions> options,
		ILogger<CachingApiKeyClientResolver> logger) {
		this._inner = inner ?? throw new ArgumentNullException(nameof(inner));
		this._cache = cache ?? throw new ArgumentNullException(nameof(cache));
		this._options = options?.Value ?? new ApiKeySourceCachingOptions();
		this._logger = logger ?? throw new ArgumentNullException(nameof(logger));
		this._ownsCache = false;
	}

	/// <summary>
	/// Initializes a new instance with a dedicated, size-bounded cache (the standard path).
	/// </summary>
	/// <param name="inner">The inner resolver to cache.</param>
	/// <param name="options">The caching options.</param>
	/// <param name="logger">The logger.</param>
	public CachingApiKeyClientResolver(
		IApiKeyClientResolver inner,
		IOptions<ApiKeySourceCachingOptions> options,
		ILogger<CachingApiKeyClientResolver> logger)
		: this(
			inner,
			new MemoryCache(new MemoryCacheOptions { SizeLimit = options?.Value?.MaxCacheEntries ?? 10_000 }),
			options ?? Options.Create(new ApiKeySourceCachingOptions()),
			logger) {
		this._ownsCache = true;
	}

	/// <inheritdoc/>
	public async Task<ApiKeyResolveResult> ResolveAsync(
		string providedKey,
		ApiKeyLookupContext context,
		CancellationToken cancellationToken = default) {

		var headerName = context.HeaderName;
		var clientId = context.GetHeader(ApiKeyHeaders.ClientId);
		var cacheKey = GenerateCacheKey(context.RequestedSource, clientId, headerName, providedKey);

		// Try to get from cache
		if (this._cache.TryGetValue(cacheKey, out var cached)) {
			if (cached is ApiKeyClient client) {
				// Defense-in-depth expiry recheck on a cache hit (M3): a client cached while valid must not
				// be replayed past its own expiry. The handler chokepoint also re-checks expiry, but evicting
				// here keeps the cache honest and reclaims the slot. An expired entry is treated as a miss.
				// Deliberately uses the raw ExpiresAt, not the validator's expiry+grace window: the direction
				// is conservative (it only ever drops a still-valid entry and re-resolves, never serves an
				// over-expiry one — the handler remains the authority), at the cost of not caching a
				// credential during any configured grace window (typically zero).
				if (client.ExpiresAt is { } exp && exp <= DateTimeOffset.UtcNow) {
					this._cache.Remove(cacheKey);
				} else {
					if (this._logger.IsEnabled(LogLevel.Debug)) {
						this._logger.LogDebug(
							"API key cache hit for header {HeaderName}: ClientId={ClientId}",
							headerName,
							client.ClientId);
					}
					return ApiKeyResolveResult.Success(client);
				}
			} else if (cached is string marker && marker == NotFoundMarker) {
				if (this._logger.IsEnabled(LogLevel.Debug)) {
					this._logger.LogDebug(
						"API key cache hit (negative) for header {HeaderName}",
						headerName);
				}
				return ApiKeyResolveResult.NotFound();
			}
		}

		// Cache miss - resolve from inner
		var result = await this._inner.ResolveAsync(providedKey, context, cancellationToken);

		// Cache the result
		if (result.IsSuccess && result.Client is not null) {
			// Cap the entry's life at the credential's own expiry (M3): never cache a success for longer
			// than the credential is valid, and skip caching one that is already expired (the handler
			// rejects it anyway). A null ExpiresAt keeps the configured SuccessCacheDuration.
			var duration = this._options.SuccessCacheDuration;
			var cacheable = true;
			if (result.Client.ExpiresAt is { } exp) {
				var untilExpiry = exp - DateTimeOffset.UtcNow;
				if (untilExpiry <= TimeSpan.Zero) {
					cacheable = false;
				} else if (untilExpiry < duration) {
					duration = untilExpiry;
				}
			}

			if (cacheable) {
				var entryOptions = new MemoryCacheEntryOptions()
					.SetAbsoluteExpiration(duration)
					.SetSize(1);

				this._cache.Set(cacheKey, result.Client, entryOptions);

				if (this._logger.IsEnabled(LogLevel.Debug)) {
					this._logger.LogDebug(
						"API key cached for header {HeaderName}: ClientId={ClientId}, Duration={Duration}",
						headerName,
						result.Client.ClientId,
						duration);
				}
			}
		} else if (!result.IsSuccess && this._options.EnableNegativeCaching) {
			var entryOptions = new MemoryCacheEntryOptions()
				.SetAbsoluteExpiration(this._options.NotFoundCacheDuration)
				.SetSize(1);

			this._cache.Set(cacheKey, NotFoundMarker, entryOptions);

			if (this._logger.IsEnabled(LogLevel.Debug)) {
				this._logger.LogDebug(
					"API key negative cached for header {HeaderName}, Duration={Duration}",
					headerName,
					this._options.NotFoundCacheDuration);
			}
		}

		return result;
	}

	/// <summary>
	/// Generates a cache key from the routing dimension (<c>X-Api-Source</c>-derived store ref), the
	/// client index (<c>X-Client-Id</c>), the header name, and the provided key. Uses a SHA256 hash to
	/// avoid storing raw keys in cache.
	/// </summary>
	/// <remarks>
	/// Both the <paramref name="requestedSource"/> and the <paramref name="clientId"/> are part of the
	/// lookup identity: the same key resolves to a different client (or to a miss) depending on which store
	/// it is routed to <em>and</em> which client index it is presented under, so a result cached under one
	/// (source, client-id) tuple must never satisfy a lookup under another. Omitting the client index would
	/// let two callers presenting the same key string with different <c>X-Client-Id</c> values collide on
	/// one entry — authenticating one client as the other within the cache TTL (N16).
	/// </remarks>
	private static string GenerateCacheKey(string? requestedSource, string? clientId, string headerName, string providedKey) {
		// Length-prefix each segment so distinct (source, client-id, header) tuples can never collide via a
		// delimiter that also appears inside a value.
		var combined =
			$"{requestedSource?.Length ?? -1}:{requestedSource}:" +
			$"{clientId?.Length ?? -1}:{clientId}:" +
			$"{headerName.Length}:{headerName}:{providedKey}";
		var bytes = Encoding.UTF8.GetBytes(combined);
		var hash = SHA256.HashData(bytes);
		return $"{CacheKeyPrefix}{Convert.ToBase64String(hash)}";
	}

	/// <inheritdoc/>
	public void Dispose() {
		if (this._ownsCache && this._cache is IDisposable disposable) {
			disposable.Dispose();
		}
	}
}
