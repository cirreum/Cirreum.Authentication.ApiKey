namespace Cirreum.Authentication.ApiKey.Tests;

using Cirreum.Authentication.Configuration;
using Microsoft.Extensions.Configuration;

/// <summary>
/// Proofs that the <c>Validation</c> and <c>Revocation</c> knobs bind as nested sub-objects of the
/// provider settings (one bind from <c>Cirreum:Authentication:Providers:ApiKey</c>), rather than via a
/// separate hand-crafted config read — and that their defaults survive when the sub-sections are absent.
/// </summary>
public sealed class ApiKeyAuthenticationSettingsBindingTests {

	private static ApiKeyAuthenticationSettings Bind(Dictionary<string, string?> values) =>
		new ConfigurationBuilder().AddInMemoryCollection(values).Build().Get<ApiKeyAuthenticationSettings>()!;

	[Fact]
	public void Validation_and_Revocation_bind_from_their_sub_sections() {
		var settings = Bind(new Dictionary<string, string?> {
			["BearerPrefix"] = "ak_prod_",
			["Validation:AllowWeakConfiguredKeys"] = "true",
			["Validation:MinimumKeyLength"] = "48",
			["Revocation:AllowFaultedDenylist"] = "true",
			["Revocation:MaxDenylistEntries"] = "500",
		});

		settings.BearerPrefix.Should().Be("ak_prod_");
		settings.Validation.AllowWeakConfiguredKeys.Should().BeTrue();
		settings.Validation.MinimumKeyLength.Should().Be(48);
		settings.Revocation.AllowFaultedDenylist.Should().BeTrue();
		settings.Revocation.MaxDenylistEntries.Should().Be(500);
	}

	[Fact]
	public void Validation_and_Revocation_keep_their_defaults_when_absent() {
		var settings = Bind(new Dictionary<string, string?> { ["BearerPrefix"] = "ak_prod_" });

		settings.Validation.AllowWeakConfiguredKeys.Should().BeFalse();
		settings.Validation.MinimumKeyEntropyBits.Should().Be(DefaultApiKeyGenerator.MinimumEntropyBits);
		settings.Revocation.AllowFaultedDenylist.Should().BeFalse();
		settings.Revocation.MaxDenylistEntries.Should().Be(1_000_000);
	}
}
