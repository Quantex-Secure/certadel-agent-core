using System.Text.Json.Nodes;

using AcmeManager.Service.Handoff;

namespace AcmeManager.Tests.Unit;

public sealed class HandoffTests
{
    [Fact]
    public void RenewalDomains_IncludesCommonNameSansAndSiteHosts()
    {
        var root = JsonNode.Parse(
            """{ "Id":"x", "TargetPluginOptions": { "CommonName":"a.example.com", "AlternativeNames":["a.example.com","b.example.com"], "SiteId":5 } }""")!
            .AsObject();

        var domains = HandoffService.RenewalDomains(root, sid => sid == "5" ? ["site.example.com"] : []).ToList();

        Assert.Contains("a.example.com", domains);
        Assert.Contains("b.example.com", domains);
        Assert.Contains("site.example.com", domains);
    }

    [Fact]
    public void RenewalDomains_AnyHostIisRenewal_ResolvesFromSiteBindings()
    {
        // The "(any host)" case that handoff was missing: no CommonName/AlternativeNames,
        // domains come only from the IIS site's bindings (IncludeSiteIds).
        var root = JsonNode.Parse("""{ "TargetPluginOptions": { "IncludeSiteIds":["7"] } }""")!.AsObject();

        var domains = HandoffService.RenewalDomains(root, sid => sid == "7" ? ["fallingapples.example.com"] : []).ToList();

        Assert.Equal(["fallingapples.example.com"], domains);
    }

    [Fact]
    public void WinAcmeCancel_QuotesDashLeadingId()
    {
        var (_, args) = HandoffService.WinAcmeCancel("-1YJikBQ10apRQOLw5L_ig");
        // win-acme reads a bare "-…" as an option; the value must be literally quoted.
        Assert.Equal(["--cancel", "--id", "\"-1YJikBQ10apRQOLw5L_ig\""], args);
    }

    [Fact]
    public void WinAcmeCancel_LeavesPlainIdUnquoted()
    {
        var (_, args) = HandoffService.WinAcmeCancel("Ec6UGr_2kkOYAWp8HZfgMA");
        Assert.Equal(["--cancel", "--id", "Ec6UGr_2kkOYAWp8HZfgMA"], args);
    }

    [Fact]
    public void DomainsOf_ExtractsCnAndSans()
    {
        var domains = HandoffService.DomainsOf(
            "CN=blockdrop.example.com",
            """["blockdrop.example.com","www.blockdrop.example.com"]""").ToList();

        Assert.Contains("blockdrop.example.com", domains);
        Assert.Contains("www.blockdrop.example.com", domains);
    }

    [Fact]
    public void DomainsOf_ToleratesMalformedSans()
    {
        var domains = HandoffService.DomainsOf("CN=x.com", "not json").ToList();
        Assert.Equal(["x.com"], domains);
    }

    [Theory]
    [InlineData("/root/.acme.sh/x.com_ecc/x.com.conf", true)]
    [InlineData("/home/admin/.acme.sh/x.com/x.com.conf", false)]
    public void IsEcc_DetectedFromEccDirectory(string confPath, bool expected) =>
        Assert.Equal(expected, HandoffService.IsEcc(confPath));
}