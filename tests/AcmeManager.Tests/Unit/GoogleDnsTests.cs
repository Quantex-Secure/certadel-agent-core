using AcmeManager.Plugins.Dns.Google;

namespace AcmeManager.Tests.Unit;

public sealed class GoogleDnsTests
{
    private static readonly (string Name, string DnsName)[] Zones =
    [
        ("example-com", "example.com."),
        ("sub-example-com", "sub.example.com."),
        ("example-org", "example.org."),
    ];

    [Theory]
    [InlineData("_acme-challenge.example.com", "example-com")]
    [InlineData("_acme-challenge.www.example.com", "example-com")]
    [InlineData("_acme-challenge.host.sub.example.com", "sub-example-com")] // longest suffix wins
    [InlineData("_acme-challenge.nope.net", null)]
    public void BestZoneMatch_PicksLongestSuffixZone(string fqdn, string? expectedZoneName) =>
        Assert.Equal(expectedZoneName, GoogleDns01Validator.BestZoneMatch(Zones, fqdn));

    [Fact]
    public void BestZoneMatch_OverrideWins()
    {
        var name = GoogleDns01Validator.BestZoneMatch(Zones, "_acme-challenge.example.com", overrideDnsName: "example.org");
        Assert.Equal("example-org", name);
    }

    [Fact]
    public void QuoteTxt_WrapsInQuotes()
    {
        Assert.Equal("\"the-digest\"", GoogleDns01Validator.QuoteTxt("the-digest"));
    }
}