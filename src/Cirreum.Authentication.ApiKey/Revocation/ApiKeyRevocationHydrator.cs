namespace Cirreum.Authentication.ApiKey;

using Cirreum.AuthenticationProvider;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

/// <summary>
/// Hydrates the <see cref="IApiKeyDenylist"/> at startup from any registered
/// <see cref="IRevokedCredentialProvider"/> (ADR-0020 §8), so credentials revoked while this head was
/// down are denied immediately after a restart — without waiting for a replayed event. A provider
/// that fails is logged and skipped (availability over a brief revocation gap that the live
/// <c>CredentialRevoked</c> event stream and per-request validation continue to close).
/// </summary>
internal sealed class ApiKeyRevocationHydrator(
	IEnumerable<IRevokedCredentialProvider> providers,
	IApiKeyDenylist denylist,
	ILogger<ApiKeyRevocationHydrator> logger) : IHostedService {

	/// <inheritdoc />
	public async Task StartAsync(CancellationToken cancellationToken) {
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
				logger.LogError(ex,
					"Failed to hydrate revoked ApiKey credentials from {Provider}; revoked credentials may be " +
					"accepted until a CredentialRevoked event arrives.", providerName);
			}
		}
	}

	/// <inheritdoc />
	public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

}
