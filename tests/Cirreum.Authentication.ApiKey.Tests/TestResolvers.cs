namespace Cirreum.Authentication.ApiKey.Tests;

using Cirreum.AuthenticationProvider;

/// <summary>Shared <see cref="IApiKeyClientResolver"/> test doubles and context builders.</summary>
internal static class TestResolvers {

	public static ApiKeyLookupContext Context(
		string headerName = "Authorization",
		CredentialTransport transport = CredentialTransport.BearerAuthorizationHeader,
		string? requestedSource = null,
		IApiKeySource? resolvedSource = null,
		IReadOnlyDictionary<string, string>? headers = null) =>
		new(transport, headerName, headers ?? new Dictionary<string, string>(), requestedSource, resolvedSource);

	public static ApiKeyClient Client(string clientId = "client-1") =>
		new() { ClientId = clientId, ClientName = clientId };

	/// <summary>A resolver that returns a fixed result and counts invocations.</summary>
	public sealed class Stub(ApiKeyResolveResult result) : IApiKeyClientResolver {
		public int Calls { get; private set; }

		public Task<ApiKeyResolveResult> ResolveAsync(
			string providedKey, ApiKeyLookupContext context, CancellationToken cancellationToken = default) {
			this.Calls++;
			return Task.FromResult(result);
		}
	}

	/// <summary>A resolver that throws a non-cancellation exception.</summary>
	public sealed class Throwing : IApiKeyClientResolver {
		public int Calls { get; private set; }

		public Task<ApiKeyResolveResult> ResolveAsync(
			string providedKey, ApiKeyLookupContext context, CancellationToken cancellationToken = default) {
			this.Calls++;
			throw new InvalidOperationException("backing store unavailable");
		}
	}

	/// <summary>A resolver that honors cancellation by throwing when its token is cancelled.</summary>
	public sealed class CancelObserving : IApiKeyClientResolver {
		public Task<ApiKeyResolveResult> ResolveAsync(
			string providedKey, ApiKeyLookupContext context, CancellationToken cancellationToken = default) {
			cancellationToken.ThrowIfCancellationRequested();
			return Task.FromResult(ApiKeyResolveResult.NotFound());
		}
	}
}
