namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// The authoritative, in-memory registry of API key sources (ADR-0020 §6). It is the single source
/// of truth for store routing and is surfaced to self-service UIs (via a Query Operation) — never
/// synced to a database, which would re-introduce drift.
/// </summary>
public interface IApiKeySourceCatalog {

	/// <summary>All registered sources.</summary>
	IReadOnlyCollection<IApiKeySource> Sources { get; }

	/// <summary>
	/// Finds a source by its opaque <see cref="IApiKeySource.SourceRef"/>, or <see langword="null"/>
	/// when no source matches.
	/// </summary>
	IApiKeySource? FindByRef(string sourceRef);

}
