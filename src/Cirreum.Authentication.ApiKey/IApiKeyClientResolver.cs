namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Resolves and validates API key clients from various sources (configuration, database, etc.).
/// </summary>
public interface IApiKeyClientResolver {

	/// <summary>
	/// Resolves and validates an API key, returning the associated client if valid.
	/// </summary>
	/// <param name="providedKey">The API key value to validate.</param>
	/// <param name="context">
	/// Context containing the header name and additional request headers
	/// that can be used to optimize lookups (e.g., X-Client-Id for filtering).
	/// </param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>A result indicating success with client details, or failure with reason.</returns>
	Task<ApiKeyResolveResult> ResolveAsync(
		string providedKey,
		ApiKeyLookupContext context,
		CancellationToken cancellationToken = default);
}
