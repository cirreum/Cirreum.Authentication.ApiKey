namespace Cirreum.Authentication.ApiKey.Tests;

using Cirreum.AuthenticationProvider;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Proofs for <see cref="ScopedApiKeyClientResolver"/> (N10): an app resolver with a scoped dependency is
/// resolved in a fresh per-resolution scope, never captured on the root container. The provider is built
/// with <c>ValidateScopes = true</c> — the way scoping bugs surface in Development — so a root-container
/// resolution of the scoped dependency would throw.
/// </summary>
public sealed class ScopedApiKeyClientResolverTests {

	private sealed class CreationTracker {
		public int Count;
	}

	private sealed class ScopedDependency {
		public ScopedDependency(CreationTracker tracker) => Interlocked.Increment(ref tracker.Count);
	}

	private sealed class AppResolver(ScopedDependency dependency) : IApiKeyClientResolver {
		public Task<ApiKeyResolveResult> ResolveAsync(
			string providedKey, ApiKeyLookupContext context, CancellationToken cancellationToken = default) {
			_ = dependency; // proves the scoped dependency was injected
			return Task.FromResult(ApiKeyResolveResult.Success(TestResolvers.Client("scoped")));
		}
	}

	[Fact]
	public async Task Each_resolution_runs_the_app_resolver_in_a_fresh_scope_no_capture() {
		var tracker = new CreationTracker();
		var services = new ServiceCollection();
		services.AddSingleton(tracker);
		services.AddScoped<ScopedDependency>();
		services.AddScoped<AppResolver>();

		// ValidateScopes = true makes any root-container resolution of a scoped service throw — so a passing
		// run proves the bridge resolves from a scope, not the captured root provider.
		var sp = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
		var bridge = new ScopedApiKeyClientResolver(sp.GetRequiredService<IServiceScopeFactory>(), typeof(AppResolver));

		var first = await bridge.ResolveAsync("k", TestResolvers.Context());
		var second = await bridge.ResolveAsync("k", TestResolvers.Context());

		first.IsSuccess.Should().BeTrue();
		second.IsSuccess.Should().BeTrue();
		tracker.Count.Should().Be(2,
			"a fresh scope (and a fresh scoped dependency) is created per resolution — the resolver is never captured");
	}
}
