namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Options for API key resolution caching behavior.
/// </summary>
public sealed class ApiKeyCachingOptions {

	/// <summary>
	/// Gets or sets the duration to cache successful resolutions.
	/// Default is 5 minutes.
	/// </summary>
	public TimeSpan SuccessCacheDuration { get; set; } = TimeSpan.FromMinutes(5);

	/// <summary>
	/// Gets or sets the duration to cache "not found" results to prevent
	/// repeated database lookups for invalid keys.
	/// Default is 30 seconds.
	/// </summary>
	public TimeSpan NotFoundCacheDuration { get; set; } = TimeSpan.FromSeconds(30);

	/// <summary>
	/// Gets or sets whether to cache "not found" results (negative caching).
	/// Helps prevent repeated database lookups for invalid keys.
	/// Default is <see langword="true"/>.
	/// </summary>
	public bool EnableNegativeCaching { get; set; } = true;

	/// <summary>
	/// Gets or sets the maximum number of entries to cache.
	/// Default is 10,000.
	/// </summary>
	public int MaxCacheEntries { get; set; } = 10_000;
}
