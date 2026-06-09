namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Default <see cref="IApiKeySource"/> record. Dynamic sources are addressable-only; the resolver
/// for a dynamic source is registered in DI keyed by <see cref="SourceRef"/>.
/// </summary>
public sealed record ApiKeySource : IApiKeySource {

	/// <inheritdoc />
	public required string FriendlyName { get; init; }

	/// <inheritdoc />
	public required string SourceRef { get; init; }

	/// <inheritdoc />
	public required ApiKeySourceKind Kind { get; init; }

	/// <inheritdoc />
	public bool IsAddressableOnly => this.Kind == ApiKeySourceKind.Dynamic;

}
