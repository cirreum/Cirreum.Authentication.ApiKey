namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Default <see cref="IApiKeySource"/> record. A named, addressable source whose resolver is registered
/// in DI keyed by <see cref="SourceRef"/>.
/// </summary>
public sealed record ApiKeySource : IApiKeySource {

	/// <inheritdoc />
	public required string FriendlyName { get; init; }

	/// <inheritdoc />
	public required string SourceRef { get; init; }

	/// <inheritdoc />
	public bool RequireClientId { get; init; }

}
