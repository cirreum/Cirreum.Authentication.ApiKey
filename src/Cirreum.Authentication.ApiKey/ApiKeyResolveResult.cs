namespace Cirreum.Authentication.ApiKey;

/// <summary>
/// Represents the result of an API key resolution attempt.
/// </summary>
public sealed record ApiKeyResolveResult {

	/// <summary>
	/// Gets whether the resolution was successful.
	/// </summary>
	public bool IsSuccess { get; private init; }

	/// <summary>
	/// Gets the resolved client when successful; otherwise, <see langword="null"/>.
	/// </summary>
	public ApiKeyClient? Client { get; private init; }

	/// <summary>
	/// Gets the reason for failure when unsuccessful; otherwise, <see langword="null"/>.
	/// </summary>
	public string? FailureReason { get; private init; }

	private ApiKeyResolveResult() { }

	/// <summary>
	/// Creates a successful resolution result.
	/// </summary>
	/// <param name="client">The resolved client.</param>
	/// <returns>A successful result containing the client.</returns>
	public static ApiKeyResolveResult Success(ApiKeyClient client) =>
		new() {
			IsSuccess = true,
			Client = client ?? throw new ArgumentNullException(nameof(client))
		};

	/// <summary>
	/// Creates a failed resolution result with a reason.
	/// </summary>
	/// <param name="reason">The reason for failure.</param>
	/// <returns>A failed result with the specified reason.</returns>
	public static ApiKeyResolveResult Failed(string reason) =>
		new() {
			IsSuccess = false,
			FailureReason = reason ?? throw new ArgumentNullException(nameof(reason))
		};

	/// <summary>
	/// Creates a result indicating the key was not found.
	/// </summary>
	/// <returns>A failed result indicating not found.</returns>
	public static ApiKeyResolveResult NotFound() =>
		new() {
			IsSuccess = false,
			FailureReason = "API key not found"
		};

	/// <summary>
	/// Creates a result indicating the key has expired.
	/// </summary>
	/// <returns>A failed result indicating expiration.</returns>
	public static ApiKeyResolveResult Expired() =>
		new() {
			IsSuccess = false,
			FailureReason = "API key has expired"
		};
}
