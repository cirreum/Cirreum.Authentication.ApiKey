namespace Cirreum.Authentication.ApiKey;

using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

/// <summary>
/// Reports the authority of the ApiKey revocation denylist (ADR-0020 §8) so an orchestrator can pull
/// an instance whose denylist is not trustworthy. Registered under the name
/// <see cref="Name"/> by <c>AddApiKey(...)</c>.
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><c>Healthy</c> — hydration completed; the denylist is authoritative.</item>
///   <item><c>Degraded</c> — still hydrating (transient at startup), or faulted with
///   <c>AllowFaultedDenylist</c> set (serving with a possibly-incomplete denylist).</item>
///   <item><c>Unhealthy</c> — hydration faulted and ApiKey auth is failing closed (<c>503</c>);
///   fix the revoked-credential provider and restart.</item>
/// </list>
/// </remarks>
internal sealed class ApiKeyRevocationHealthCheck(
	ApiKeyRevocationReadiness readiness,
	IApiKeyDenylist denylist,
	IOptions<ApiKeyRevocationOptions> options
) : IHealthCheck {

	/// <summary>The registered health-check name.</summary>
	public const string Name = "apikey-revocation";

	private readonly ApiKeyRevocationOptions _options = options.Value;

	/// <inheritdoc />
	public Task<HealthCheckResult> CheckHealthAsync(
		HealthCheckContext context,
		CancellationToken cancellationToken = default) {

		if (!denylist.IsAuthoritative) {
			// The denylist saturated and had to refuse a revocation — it may be missing a revoked credential,
			// so ApiKey auth is failing closed (503). Raise the cap / move to a scale-out denylist, then restart (N18).
			return Task.FromResult(HealthCheckResult.Unhealthy(
				"ApiKey revocation denylist saturated and refused a revocation; ApiKey authentication is failing " +
				"closed (503). Raise Cirreum:Authentication:Providers:ApiKey:Revocation:MaxDenylistEntries or move to " +
				"a scale-out denylist, then restart."));
		}

		if (readiness.Faulted) {
			return Task.FromResult(this._options.AllowFaultedDenylist
				? HealthCheckResult.Degraded(
					"ApiKey revocation hydration faulted; serving with a possibly-incomplete denylist " +
					"(AllowFaultedDenylist is set). A revoked credential may authenticate until the live " +
					"revocation event stream catches up.")
				: HealthCheckResult.Unhealthy(
					"ApiKey revocation hydration faulted; ApiKey authentication is failing closed (503). " +
					"Fix the revoked-credential provider and restart."));
		}

		if (!readiness.IsReady) {
			return Task.FromResult(HealthCheckResult.Degraded(
				"ApiKey revocation denylist is still hydrating; ApiKey authentication is failing closed (503)."));
		}

		return Task.FromResult(HealthCheckResult.Healthy("ApiKey revocation denylist is authoritative."));
	}
}
