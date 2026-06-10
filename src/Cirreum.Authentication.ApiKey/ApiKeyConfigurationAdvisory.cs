namespace Cirreum.Authentication.ApiKey;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Emits a one-time, boot-time advisory for ApiKey validation posture that has been dialed down from the
/// secure defaults, so a relaxation is <em>loud</em> rather than silent (L1) and an unset cryptoperiod is
/// surfaced (SP 800-57; I-d). Runs once at startup and does nothing thereafter — purely observational, it
/// never changes the authentication decision.
/// </summary>
internal sealed class ApiKeyConfigurationAdvisory(
	IOptions<ApiKeyValidationOptions> validationOptions,
	ILogger<ApiKeyConfigurationAdvisory> logger
) : IHostedService {

	/// <inheritdoc />
	public Task StartAsync(CancellationToken cancellationToken) {
		var v = validationOptions.Value;

		if (v.AllowExpiredKeys) {
			logger.LogWarning(
				"ApiKey: AllowExpiredKeys is set — key expiry AND the SP 800-57 cryptoperiod (MaxKeyAge) are " +
				"disabled; an expired credential will authenticate indefinitely. Intended for non-production only.");
		}

		if (v.AllowWeakConfiguredKeys) {
			logger.LogWarning(
				"ApiKey: AllowWeakConfiguredKeys is set — the configured-key strength floors (minimum length and " +
				"estimated entropy) are disabled; weak appsettings keys can authenticate. Intended for non-production only.");
		}

		if (!v.RequireExpiry && v.MaxKeyAge is null && !v.AllowExpiredKeys) {
			logger.LogInformation(
				"ApiKey: no cryptoperiod is enforced (RequireExpiry is false and MaxKeyAge is unset), so keys never " +
				"expire by policy (NIST SP 800-57). Set RequireExpiry and/or MaxKeyAge to bound key lifetime.");
		}

		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
