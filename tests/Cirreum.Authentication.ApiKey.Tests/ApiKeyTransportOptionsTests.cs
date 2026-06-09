namespace Cirreum.Authentication.ApiKey.Tests;

/// <summary>
/// Proofs for the transport-selection DX on <see cref="ApiKeyOptions"/>: the all-well-known default,
/// <c>AcceptTransports</c> as a restriction (empty = clear), <c>AddCustomTransport</c> as always-additive,
/// and the enum → header-name mapping the registrar uses.
/// </summary>
public sealed class ApiKeyTransportOptionsTests {

	[Fact]
	public void By_default_all_well_known_transports_are_accepted() {
		var options = new ApiKeyOptions();

		options.AcceptedTransports.Should().BeEquivalentTo(new[] {
			ApiKeyTransport.Bearer,
			ApiKeyTransport.XApiKey,
			ApiKeyTransport.OcpApimSubscriptionKey,
			ApiKeyTransport.XAuthToken,
		});
		options.CustomHeaders.Should().BeEmpty();
	}

	[Fact]
	public void AcceptTransports_restricts_to_the_listed_set() {
		var options = new ApiKeyOptions();
		options.AcceptTransports(ApiKeyTransport.Bearer, ApiKeyTransport.XApiKey);

		options.AcceptedTransports.Should().Equal(ApiKeyTransport.Bearer, ApiKeyTransport.XApiKey);
	}

	[Fact]
	public void AcceptTransports_with_no_arguments_clears_the_well_known_set() {
		var options = new ApiKeyOptions();
		options.AcceptTransports();

		options.AcceptedTransports.Should().BeEmpty("an empty call is the explicit 'accept none of the well-known' gesture");
	}

	[Fact]
	public void AcceptTransports_dedupes() {
		var options = new ApiKeyOptions();
		options.AcceptTransports(ApiKeyTransport.Bearer).AcceptTransports(ApiKeyTransport.Bearer);

		options.AcceptedTransports.Should().ContainSingle().Which.Should().Be(ApiKeyTransport.Bearer);
	}

	[Fact]
	public void AddCustomTransport_is_additive_and_does_not_restrict() {
		var options = new ApiKeyOptions();
		options.AddCustomTransport("X-Partner-Key");

		options.AcceptedTransports.Should().HaveCount(4, "a custom header never removes the well-known transports");
		options.CustomHeaders.Should().ContainSingle().Which.Should().Be("X-Partner-Key");
	}

	[Fact]
	public void AddCustomTransport_dedupes_case_insensitively() {
		var options = new ApiKeyOptions();
		options.AddCustomTransport("X-Partner-Key").AddCustomTransport("x-partner-key");

		options.CustomHeaders.Should().ContainSingle();
	}

	[Theory]
	[InlineData("")]
	[InlineData("   ")]
	public void AddCustomTransport_rejects_blank_headers(string headerName) {
		var act = () => new ApiKeyOptions().AddCustomTransport(headerName);
		act.Should().Throw<ArgumentException>();
	}

	[Theory]
	[InlineData(ApiKeyTransport.XApiKey, "X-Api-Key")]
	[InlineData(ApiKeyTransport.OcpApimSubscriptionKey, "Ocp-Apim-Subscription-Key")]
	[InlineData(ApiKeyTransport.XAuthToken, "X-Auth-Token")]
	public void HeaderName_maps_each_header_transport(ApiKeyTransport transport, string expected) {
		transport.HeaderName().Should().Be(expected);
	}

	[Fact]
	public void HeaderName_throws_for_Bearer() {
		var act = () => ApiKeyTransport.Bearer.HeaderName();
		act.Should().Throw<ArgumentOutOfRangeException>("Bearer has no custom header — it uses the Bearer registration path");
	}
}
