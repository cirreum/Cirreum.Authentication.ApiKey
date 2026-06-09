namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// The typed outcome of an <see cref="IApiKeyClientResolver"/> resolution. The discriminator the
/// <see cref="CompositeApiKeyClientResolver"/> branches on — only <see cref="NotFound"/> means "this
/// resolver did not own the credential, try the next one"; every other outcome is a definitive answer
/// for this credential and short-circuits the chain. Branching on this enum (not a free-text
/// <c>FailureReason</c>) keeps a resolver's diagnostic wording from silently changing control flow.
/// </summary>
public enum ApiKeyResolveOutcome {

	/// <summary>The credential matched and validated; <see cref="ApiKeyResolveResult.Client"/> is set.</summary>
	Success,

	/// <summary>
	/// The credential was not found in this resolver. The only soft outcome: the composite chain
	/// continues to the next resolver. Never leaks whether any other store holds the credential.
	/// </summary>
	NotFound,

	/// <summary>The credential matched a store but has expired. Definitive — stops the chain.</summary>
	Expired,

	/// <summary>A hard failure resolving the credential (e.g. a store-level rejection). Stops the chain.</summary>
	Failed,

	/// <summary>
	/// No routing signal was supplied while addressable stores exist (ADR-0020 §5). The handler maps
	/// this to a non-descript <c>400</c> rather than a <c>401</c>. Stops the chain.
	/// </summary>
	MissingRoutingSignal,

	/// <summary>
	/// The revocation denylist is not authoritative yet (boot hydration is incomplete, or it faulted
	/// and <c>AllowFaultedDenylist</c> is off). Authentication fails closed: the handler maps this to a
	/// <c>503</c> (retry) rather than a <c>401</c>, since the credential itself was never evaluated —
	/// we simply cannot prove it is not revoked (ADR-0020 §8). Stops the chain.
	/// </summary>
	RevocationUnavailable,
}
