namespace Cirreum.Authentication.ApiKey.Tests;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Composition-path proofs for <c>AddApiKey()</c>: the full registration graph must compose on a bare
/// host (no ApiKey configuration section) and yield a resolvable container. Guards the factory-descriptor
/// regression (GitHub issue #1) where <c>TryAddEnumerable</c> rejected the PBKDF2 hasher registration and
/// every <c>AddApiKey(...)</c> call threw <c>ArgumentException</c> before <c>Build()</c>.
/// </summary>
public sealed class ApiKeyCompositionTests {

	private static IAuthenticationBuilder CreateBuilder(IServiceCollection services, IConfiguration? configuration = null) {
		var builder = Substitute.For<IAuthenticationBuilder>();
		builder.Services.Returns(services);
		builder.AuthBuilder.Returns(new AuthenticationBuilder(services));
		builder.Configuration.Returns(configuration ?? new ConfigurationBuilder().Build());
		return builder;
	}

	[Fact]
	public void AddApiKey_composes_without_throwing_on_a_bare_host() {
		var services = new ServiceCollection();
		var builder = CreateBuilder(services);

		var act = () => builder.AddApiKey();

		act.Should().NotThrow();
	}

	[Fact]
	public void AddApiKey_registers_both_self_describing_hashers() {
		var services = new ServiceCollection();
		var builder = CreateBuilder(services);

		builder.AddApiKey();

		using var provider = services.BuildServiceProvider();
		List<IApiKeyHasher> hashers = [.. provider.GetServices<IApiKeyHasher>()];

		hashers.Should().HaveCount(2);
		hashers.Should().ContainSingle(h => h is Sha256ApiKeyHasher);
		hashers.Should().ContainSingle(h => h is Pbkdf2ApiKeyHasher);
	}

	[Fact]
	public void AddApiKey_called_twice_throws_the_composition_guard() {
		var services = new ServiceCollection();
		var builder = CreateBuilder(services);
		builder.AddApiKey();

		var act = () => builder.AddApiKey();

		act.Should().Throw<InvalidOperationException>()
			.WithMessage("*already been called*");
	}
}
