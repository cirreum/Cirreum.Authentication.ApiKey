namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Default <see cref="IApiKeySourceCatalog"/> — a singleton populated during <c>AddApiKey(...)</c>
/// composition. Registration is composition-time only; reads are lock-free thereafter.
/// </summary>
public sealed class ApiKeySourceCatalog : IApiKeySourceCatalog {

	private readonly Dictionary<string, IApiKeySource> _byRef = new(StringComparer.Ordinal);

	/// <inheritdoc />
	public IReadOnlyCollection<IApiKeySource> Sources => this._byRef.Values;

	/// <inheritdoc />
	public IApiKeySource? FindByRef(string sourceRef) {
		if (string.IsNullOrEmpty(sourceRef)) {
			return null;
		}

		return this._byRef.TryGetValue(sourceRef, out var source) ? source : null;
	}

	/// <summary>
	/// Registers a source. Throws if two distinct friendly names derive the same
	/// <see cref="IApiKeySource.SourceRef"/> (a collision the operator must resolve by renaming).
	/// </summary>
	internal void Register(IApiKeySource source) {
		ArgumentNullException.ThrowIfNull(source);

		if (this._byRef.TryGetValue(source.SourceRef, out var existing)) {
			if (!string.Equals(existing.FriendlyName, source.FriendlyName, StringComparison.Ordinal)) {
				throw new InvalidOperationException(
					$"ApiKey source reference collision: '{existing.FriendlyName}' and " +
					$"'{source.FriendlyName}' both derive '{source.SourceRef}'. Rename one store.");
			}

			return;
		}

		this._byRef[source.SourceRef] = source;
	}

}
