namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// The backing kind of an API key source / key set (ADR-0020 §4/§5).
/// </summary>
public enum ApiKeySourceKind {

	/// <summary>
	/// A config-backed key set compared in-memory with <c>FixedTimeEquals</c>. Cheap, so it may
	/// participate in the blind fallback scan; discriminated by header name, not by <c>X-Api-Source</c>.
	/// </summary>
	Static = 0,

	/// <summary>
	/// A database-backed key set resolved at request time. Addressable-only — reached via an explicit
	/// <c>X-Api-Source</c> reference and never part of the blind fallback scan (the CPU-DoS guarantee).
	/// </summary>
	Dynamic = 1

}
