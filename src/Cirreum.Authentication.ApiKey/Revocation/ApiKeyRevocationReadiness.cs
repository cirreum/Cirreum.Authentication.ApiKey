namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Tracks whether the revocation denylist is authoritative yet (ADR-0020 §8). Written once by the
/// boot-time <see cref="ApiKeyRevocationHydrator"/> and read on every resolution by the dispatcher
/// (to gate auth) and by the health check. Until <see cref="IsReady"/>, ApiKey authentication fails
/// closed — a revoked credential must never slip through a startup race or a faulted hydration.
/// </summary>
/// <remarks>
/// Hosted-service <c>StartAsync</c> is awaited before the server accepts requests, so in normal
/// operation hydration completes before any traffic and the gate is transparent. It bites only when
/// hydration <em>faults</em> with <c>AllowFaultedDenylist</c> off — exactly the case the health check
/// reports <c>Unhealthy</c> so the instance is pulled from rotation.
/// </remarks>
internal sealed class ApiKeyRevocationReadiness {

	private volatile bool _ready;
	private volatile bool _faulted;

	/// <summary>
	/// Whether the denylist is authoritative and auth may proceed: hydration completed successfully, or
	/// it faulted but the operator opted into <c>AllowFaultedDenylist</c>.
	/// </summary>
	public bool IsReady => this._ready;

	/// <summary>Whether boot hydration faulted (a provider threw). Surfaced by the health check.</summary>
	public bool Faulted => this._faulted;

	/// <summary>Marks the denylist authoritative. Idempotent.</summary>
	public void MarkReady() => this._ready = true;

	/// <summary>Records that hydration faulted. Surfaced by the health check regardless of the escape hatch.</summary>
	public void MarkFaulted() => this._faulted = true;
}
