using AcmeManager.Plugins.Dns.Aws;

namespace AcmeManager.Tests.Unit;

public sealed class Route53DnsTests
{
    private static readonly (string Id, string Name)[] Zones =
    [
        ("Z-EXAMPLE", "example.com."),
        ("Z-SUB", "sub.example.com."),
        ("Z-EXAMPLE", "example.org."),
    ];

    [Theory]
    [InlineData("_acme-challenge.example.com", "Z-EXAMPLE")]
    [InlineData("_acme-challenge.www.example.com", "Z-EXAMPLE")]
    [InlineData("_acme-challenge.api.sub.example.com", "Z-SUB")] // longest suffix wins
    [InlineData("_acme-challenge.nope.net", null)]
    public void BestZoneMatch_PicksLongestSuffixZoneId(string fqdn, string? expectedZoneId) =>
        Assert.Equal(expectedZoneId, Route53Dns01Validator.BestZoneMatch(Zones, fqdn));
}