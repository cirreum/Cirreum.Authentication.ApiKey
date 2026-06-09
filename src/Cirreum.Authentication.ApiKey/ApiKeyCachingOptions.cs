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
	/// Gets or sets whether to cache "not found" results (negative caching). Default is
	/// <see langword="false"/>: negative caching trades a brief denial-of-correct-credential window
	/// for fewer backing-store lookups, so it is opt-in. When enabled, a miss is cached per
	/// (routing dimension, header, key) for <see cref="NotFoundCacheDuration"/>; a newly provisioned
	/// or just-rotated key can be rejected for up to that window. Enable only when the backing store
	/// is under load from invalid keys and a short staleness window is acceptable.
	/// </summary>
	public bool EnableNegativeCaching { get; set; } = false;

	/// <summary>
	/// Gets or sets the maximum number of entries to cache.
	/// Default is 10,000.
	/// </summary>
	public int MaxCacheEntries { get; set; } = 10_000;
}
