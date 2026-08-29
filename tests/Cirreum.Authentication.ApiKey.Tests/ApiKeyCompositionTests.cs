namespace Cirreum.Authentication.ApiKey.Tests;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

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

	/// <summary>
	/// Instance configuration in the natural shape of a developer user-secret: a client and its key,
	/// with no explicit <c>Enabled</c> flag. <c>Enabled</c> is an unset <c>bool</c>, so the instance is
	/// declared but disabled.
	/// </summary>
	private static IConfiguration ConfigurationWithInstance(bool? enabled) {
		const string prefix = "Cirreum:Authentication:Providers:ApiKey:Instances:broker";

		var values = new Dictionary<string, string?> {
			[$"{prefix}:ClientId"] = "broker",
			[$"{prefix}:Key"] = "k7Qm2Zt9XvB4nR8sL1dW6yH3pC0jF5gA2eU7iO9qT4xS",
		};

		if (enabled.HasValue) {
			values[$"{prefix}:Enabled"] = enabled.Value ? "true" : "false";
		}

		return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
	}

	[Fact]
	public void ApiKeyGraph_resolver_is_never_registered_without_its_registry() {
		var services = new ServiceCollection();
		var builder = CreateBuilder(services, ConfigurationWithInstance(enabled: null));

		builder.AddApiKey();

		using var provider = services.BuildServiceProvider();

		// A registered-but-unconstructible descriptor throws here rather than resolving to null, which
		// is what ApiKeySourceDispatcher's GetService call would hit on every API-key authentication.
		var act = () => provider.GetService<ConfigurationApiKeyClientResolver>();

		act.Should().NotThrow();
	}

	[Fact]
	public void AddApiKey_skips_the_configuration_resolver_when_no_instance_is_enabled() {
		var services = new ServiceCollection();
		var builder = CreateBuilder(services, ConfigurationWithInstance(enabled: false));

		builder.AddApiKey();

		services.Should().NotContain(d => d.ServiceType == typeof(ConfigurationApiKeyClientResolver));
	}

	[Fact]
	public void AddApiKey_registers_the_configuration_resolver_with_its_registry_when_an_instance_is_enabled() {
		var services = new ServiceCollection();
		services.AddLogging();
		var builder = CreateBuilder(services, ConfigurationWithInstance(enabled: true));

		builder.AddApiKey();

		using var provider = services.BuildServiceProvider();

		provider.GetService<ApiKeyClientRegistry>().Should().NotBeNull();
		provider.GetService<ConfigurationApiKeyClientResolver>().Should().NotBeNull();
	}

	[Fact]
	public void Disabled_instances_are_reported_when_every_declared_instance_is_disabled() {
		var services = new ServiceCollection();
		var builder = CreateBuilder(services, ConfigurationWithInstance(enabled: null));

		builder.AddApiKey();

		using var provider = services.BuildServiceProvider();

		provider.GetRequiredService<ApiKeyDisabledInstances>().Names.Should().Equal("broker");
	}

	[Fact]
	public void Disabled_instances_are_not_reported_when_an_instance_is_enabled() {
		var services = new ServiceCollection();
		services.AddLogging();
		var builder = CreateBuilder(services, ConfigurationWithInstance(enabled: true));

		builder.AddApiKey();

		using var provider = services.BuildServiceProvider();

		provider.GetRequiredService<ApiKeyDisabledInstances>().Names.Should().BeEmpty();
	}

	[Fact]
	public void Disabled_instances_are_not_reported_when_no_instance_is_declared() {
		var services = new ServiceCollection();
		var builder = CreateBuilder(services);

		builder.AddApiKey();

		using var provider = services.BuildServiceProvider();

		provider.GetRequiredService<ApiKeyDisabledInstances>().Names.Should().BeEmpty();
	}

	// Validator override ——————————————————————————————————————
	//
	// The validation services register with TryAdd semantics, so an application supplying its own
	// IApiKeyValidator keeps it whether it registers before AddApiKey or replaces afterwards.

	[Fact]
	public void A_validator_registered_before_AddApiKey_is_kept() {
		var services = new ServiceCollection();
		var custom = Substitute.For<IApiKeyValidator>();
		services.AddSingleton(custom);
		var builder = CreateBuilder(services);

		builder.AddApiKey();

		using var provider = services.BuildServiceProvider();

		provider.GetRequiredService<IApiKeyValidator>().Should().BeSameAs(custom);
	}

	[Fact]
	public void A_validator_replaced_after_AddApiKey_is_kept() {
		var services = new ServiceCollection();
		var builder = CreateBuilder(services);
		builder.AddApiKey();

		var custom = Substitute.For<IApiKeyValidator>();
		services.Replace(ServiceDescriptor.Singleton(custom));

		using var provider = services.BuildServiceProvider();

		provider.GetRequiredService<IApiKeyValidator>().Should().BeSameAs(custom);
	}

	[Fact]
	public async Task The_configuration_resolver_validates_through_the_replaced_validator() {
		var services = new ServiceCollection();
		services.AddLogging();
		var builder = CreateBuilder(services, ConfigurationWithInstance(enabled: true));
		builder.AddApiKey();

		var custom = Substitute.For<IApiKeyValidator>();
		custom.ValidateFormat(Arg.Any<string>())
			.Returns(ApiKeyFormatValidationResult.Invalid("rejected by the application"));
		services.Replace(ServiceDescriptor.Singleton(custom));

		using var provider = services.BuildServiceProvider();
		var resolver = provider.GetRequiredService<ConfigurationApiKeyClientResolver>();

		var result = await resolver.ResolveAsync("presented-key", TestResolvers.Context(), default);

		custom.Received(1).ValidateFormat("presented-key");
		result.IsSuccess.Should().BeFalse();
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
