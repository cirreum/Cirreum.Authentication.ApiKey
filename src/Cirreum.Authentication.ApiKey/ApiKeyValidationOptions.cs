namespace Cirreum.Authentication.ApiKey;

using Cirreum.Authentication.Configuration;
/// <summary>
/// Options for API key validation behavior.
/// </summary>
public sealed class ApiKeyValidationOptions {

	/// <summary>
	/// Gets or sets the minimum allowed key length. Default is 32 characters.
	/// </summary>
	public int MinimumKeyLength { get; set; } = 32;

	/// <summary>
	/// Gets or sets the maximum allowed key length. Default is 512 characters.
	/// </summary>
	public int MaximumKeyLength { get; set; } = 512;

	/// <summary>
	/// Gets or sets whether expired keys should be allowed.
	/// Useful for debugging scenarios. Default is <see langword="false"/>.
	/// </summary>
	/// <remarks>
	/// When enabled, expired keys will still authenticate but the expiration
	/// status may be logged for diagnostic purposes.
	/// </remarks>
	public bool AllowExpiredKeys { get; set; } = false;

	/// <summary>
	/// Gets or sets the grace period to allow after key expiration.
	/// Default is <see cref="TimeSpan.Zero"/> (no grace period).
	/// </summary>
	public TimeSpan ExpirationGracePeriod { get; set; } = TimeSpan.Zero;

	/// <summary>
	/// Gets or sets whether to enforce that keys contain only valid characters.
	/// Default is <see langword="true"/>.
	/// </summary>
	public bool EnforceValidCharacters { get; set; } = true;

	/// <summary>
	/// Gets or sets the valid characters for API keys when <see cref="EnforceValidCharacters"/> is enabled.
	/// Default includes alphanumeric characters and common safe symbols.
	/// </summary>
	public string ValidCharacters { get; set; } = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/";
}
