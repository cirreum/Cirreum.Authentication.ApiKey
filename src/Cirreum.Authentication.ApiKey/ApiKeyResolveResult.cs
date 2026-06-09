namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Represents the result of an API key resolution attempt.
/// </summary>
public sealed record ApiKeyResolveResult {

	/// <summary>
	/// Gets the typed outcome of the resolution. The composite chain branches on this, not on
	/// <see cref="FailureReason"/>.
	/// </summary>
	public ApiKeyResolveOutcome Outcome { get; private init; }

	/// <summary>
	/// Gets whether the resolution was successful.
	/// </summary>
	public bool IsSuccess => this.Outcome == ApiKeyResolveOutcome.Success;

	/// <summary>
	/// Gets the resolved client when successful; otherwise, <see langword="null"/>.
	/// </summary>
	public ApiKeyClient? Client { get; private init; }

	/// <summary>
	/// Gets the reason for failure when unsuccessful; otherwise, <see langword="null"/>.
	/// Diagnostic text only — never branch control flow on it (use <see cref="Outcome"/>).
	/// </summary>
	public string? FailureReason { get; private init; }

	/// <summary>
	/// Gets whether the failure is a missing routing signal (no <c>X-Api-Source</c> while addressable
	/// stores exist), which the handler maps to a non-descript <c>400</c> rather than a <c>401</c>.
	/// </summary>
	public bool RequiresRouting => this.Outcome == ApiKeyResolveOutcome.MissingRoutingSignal;

	private ApiKeyResolveResult() { }

	/// <summary>
	/// Creates a successful resolution result.
	/// </summary>
	/// <param name="client">The resolved client.</param>
	/// <returns>A successful result containing the client.</returns>
	public static ApiKeyResolveResult Success(ApiKeyClient client) =>
		new() {
			Outcome = ApiKeyResolveOutcome.Success,
			Client = client ?? throw new ArgumentNullException(nameof(client))
		};

	/// <summary>
	/// Creates a failed resolution result with a reason. A definitive failure for this credential —
	/// the composite chain stops here.
	/// </summary>
	/// <param name="reason">The reason for failure.</param>
	/// <returns>A failed result with the specified reason.</returns>
	public static ApiKeyResolveResult Failed(string reason) =>
		new() {
			Outcome = ApiKeyResolveOutcome.Failed,
			FailureReason = reason ?? throw new ArgumentNullException(nameof(reason))
		};

	/// <summary>
	/// Creates a result indicating the key was not found. The only soft outcome — the composite chain
	/// continues to the next resolver.
	/// </summary>
	/// <returns>A failed result indicating not found.</returns>
	public static ApiKeyResolveResult NotFound() =>
		new() {
			Outcome = ApiKeyResolveOutcome.NotFound,
			FailureReason = "API key not found"
		};

	/// <summary>
	/// Creates a result indicating the key has expired.
	/// </summary>
	/// <returns>A failed result indicating expiration.</returns>
	public static ApiKeyResolveResult Expired() =>
		new() {
			Outcome = ApiKeyResolveOutcome.Expired,
			FailureReason = "API key has expired"
		};

	/// <summary>
	/// Creates a result indicating no routing signal was supplied (an <c>ak_</c> Bearer credential
	/// reached the ApiKey scheme, no cheap store matched, addressable stores exist, and no
	/// <c>X-Api-Source</c> was provided). The handler maps this to a non-descript <c>400</c> — it
	/// must never trigger a blind scan of expensive stores, nor enumerate valid sources (ADR-0020 §5).
	/// </summary>
	public static ApiKeyResolveResult MissingRoutingSignal() =>
		new() {
			Outcome = ApiKeyResolveOutcome.MissingRoutingSignal,
			FailureReason = "Missing API key routing signal"
		};

	/// <summary>
	/// Creates a result indicating a source requiring an <c>X-Client-Id</c> index was addressed without
	/// one. The handler maps this to a non-descript <c>400</c> — the resolver is never invoked, so it is
	/// never forced to scan every client's key (ADR-0020 §6).
	/// </summary>
	public static ApiKeyResolveResult MissingClientIndex() =>
		new() {
			Outcome = ApiKeyResolveOutcome.MissingClientIndex,
			FailureReason = "Missing API key client index"
		};

	/// <summary>
	/// Creates a result indicating the revocation denylist is not authoritative yet (boot hydration
	/// incomplete or faulted with the escape hatch off). The handler maps this to a non-descript
	/// <c>503</c> — the credential was never evaluated; we cannot prove it is not revoked, so we fail
	/// closed (ADR-0020 §8).
	/// </summary>
	public static ApiKeyResolveResult RevocationUnavailable() =>
		new() {
			Outcome = ApiKeyResolveOutcome.RevocationUnavailable,
			FailureReason = "API key revocation state is temporarily unavailable"
		};
}
