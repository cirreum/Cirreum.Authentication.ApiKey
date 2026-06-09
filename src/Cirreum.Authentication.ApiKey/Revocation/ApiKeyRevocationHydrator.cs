namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Hydrates the <see cref="IApiKeyDenylist"/> at startup from any registered
/// <see cref="IRevokedCredentialProvider"/> (ADR-0020 §8), so credentials revoked while this head was
/// down are denied immediately after a restart — without waiting for a replayed event.
/// </summary>
/// <remarks>
/// <para>
/// Fail-closed by default: if any provider faults, the denylist may be missing revoked credentials, so
/// the denylist is left <em>not ready</em> — the dispatcher then fails ApiKey auth closed (a
/// <c>503</c>) and the health check reports <c>Unhealthy</c> — until the operator fixes the provider
/// and restarts. Set <see cref="ApiKeyRevocationOptions.AllowFaultedDenylist"/> to serve anyway
/// (availability over the revocation guarantee), which the health check still reports as degraded.
/// </para>
/// <para>
/// Because hosted-service <c>StartAsync</c> is awaited before the server accepts requests, a clean
/// hydration completes before any traffic and the gate is transparent. With no providers registered
/// there is nothing to hydrate and the denylist is immediately authoritative.
/// </para>
/// </remarks>
internal sealed class ApiKeyRevocationHydrator(
	IEnumerable<IRevokedCredentialProvider> providers,
	IApiKeyDenylist denylist,
	ApiKeyRevocationReadiness readiness,
	IOptions<ApiKeyRevocationOptions> options,
	ILogger<ApiKeyRevocationHydrator> logger
) : IHostedService {

	private readonly ApiKeyRevocationOptions _options = options.Value;

	/// <inheritdoc />
	public async Task StartAsync(CancellationToken cancellationToken) {
		var faulted = false;

		foreach (var provider in providers) {
			var providerName = provider.GetType().Name;
			try {
				var count = 0;
				await foreach (var credentialId in provider.GetRevokedCredentialIdsAsync(cancellationToken)) {
					denylist.Revoke(credentialId);
					count++;
				}

				if (logger.IsEnabled(LogLevel.Information)) {
					logger.LogInformation(
						"Hydrated {Count} revoked ApiKey credential(s) from {Provider}.", count, providerName);
				}
			} catch (Exception ex) when (ex is not OperationCanceledException) {
				faulted = true;
				logger.LogError(ex,
					"Failed to hydrate revoked ApiKey credentials from {Provider}.", providerName);
			}
		}

		if (faulted) {
			readiness.MarkFaulted();

			if (this._options.AllowFaultedDenylist) {
				// Operator opted into availability over the revocation guarantee. Serve, but loudly.
				logger.LogCritical(
					"ApiKey revocation hydration FAULTED but AllowFaultedDenylist is set — serving with a " +
					"possibly-incomplete denylist. A revoked credential may authenticate until the live " +
					"revocation event stream catches up. Health check is degraded.");
				readiness.MarkReady();
			} else {
				// Fail closed: leave the denylist not-ready so the dispatcher rejects ApiKey auth (503)
				// and the health check reports Unhealthy until hydration succeeds.
				logger.LogCritical(
					"ApiKey revocation hydration FAULTED — failing ApiKey authentication closed (503) and " +
					"reporting Unhealthy until hydration succeeds. Set " +
					"Cirreum:Authentication:Providers:ApiKey:Revocation:AllowFaultedDenylist=true to serve with " +
					"a possibly-incomplete denylist instead (NOT recommended).");
			}

			return;
		}

		readiness.MarkReady();
	}

	/// <inheritdoc />
	public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

}
