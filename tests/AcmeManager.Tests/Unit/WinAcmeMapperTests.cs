using System.Text.Json.Nodes;

using AcmeManager.Service.Migration.WinAcme;

namespace AcmeManager.Tests.Unit;

/// <summary>
/// WinAcmeMapper's IIS site-id → site-name/host resolution and Azure secret
/// referencing: imported renewals must be runnable as-is when the import runs on
/// the IIS box (resolvers available), reference the existing agent secret rather
/// than importing win-acme's, and carry actionable notes when context is missing.
/// </summary>
public sealed class WinAcmeMapperTests
{
    private static WinAcmeRenewal IisRenewal(int siteId, string? commonName = null)
    {
        var target = new JsonObject { ["SiteId"] = siteId };
        if (commonName is not null)
        {
            target["CommonName"] = commonName;
        }
        var root = new JsonObject
        {
            ["Id"] = "abc",
            ["LastFriendlyName"] = "[IIS] Blockdrop, (any host)",
            ["TargetPluginOptions"] = target,
            ["InstallationPluginOptions"] = new JsonArray(
                new JsonObject { ["Plugin"] = "ea6a5be3-f8de-4d27-a6bd-750b619b2ee2" }), // win-acme IIS install
        };
        return new WinAcmeRenewal("C:\\fake\\abc.renewal.json", root);
    }

    private static WinAcmeRenewal AzureValidationRenewal()
    {
        var root = new JsonObject
        {
            ["Id"] = "az",
            ["LastFriendlyName"] = "[Manual] login.example.com",
            ["TargetPluginOptions"] = new JsonObject
            {
                ["CommonName"] = "login.example.com",
                ["AlternativeNames"] = new JsonArray("login.example.com"),
            },
            ["ValidationPluginOptions"] = new JsonObject
            {
                ["TenantId"] = "tenant",
                ["ClientId"] = "client",
                ["SubscriptionId"] = "sub",
                ["ResourceGroupName"] = "example.com",
                ["HostedZone"] = "example.com",
                ["SecretSafe"] = "vault://winacme/secret", // a win-acme secret reference
            },
        };
        return new WinAcmeRenewal("C:\\fake\\az.renewal.json", root);
    }

    [Fact]
    public void Map_ResolvesIisSiteIdToName_ForSourceAndInstaller()
    {
        var ctx = new WinAcmeMapContext(ResolveSiteName: id => id == "7" ? "Blockdrop" : null);

        var mapped = WinAcmeMapper.Map(IisRenewal(7), index: 0, ctx);

        Assert.Contains("\"siteName\":\"Blockdrop\"", mapped.SourceJson, StringComparison.Ordinal);
        Assert.Contains("\"siteName\":\"Blockdrop\"", mapped.InstallationsJson, StringComparison.Ordinal);
        Assert.DoesNotContain(mapped.Notes, n => n.Contains("set the site name", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Map_FillsInstallerHost_FromTargetCommonName()
    {
        var ctx = new WinAcmeMapContext(ResolveSiteName: _ => "Blockdrop");

        var mapped = WinAcmeMapper.Map(IisRenewal(7, commonName: "blockdrop.example.com"), index: 0, ctx);

        Assert.Contains("\"host\":\"blockdrop.example.com\"", mapped.InstallationsJson, StringComparison.Ordinal);
    }

    [Fact]
    public void Map_FillsInstallerHost_FromSiteBinding_WhenTargetHasNoHostname()
    {
        // "(any host)" renewal: no CommonName, host comes from the live site binding.
        var ctx = new WinAcmeMapContext(
            ResolveSiteName: _ => "Blockdrop",
            ResolveSiteHost: name => name == "Blockdrop" ? "blockdrop.example.com" : null);

        var mapped = WinAcmeMapper.Map(IisRenewal(7), index: 0, ctx);

        Assert.Contains("\"host\":\"blockdrop.example.com\"", mapped.InstallationsJson, StringComparison.Ordinal);
    }

    [Fact]
    public void Map_WithoutResolver_LeavesSiteEmpty_AndNotes()
    {
        var mapped = WinAcmeMapper.Map(IisRenewal(7), index: 0, context: null);

        Assert.Contains("\"siteName\":\"\"", mapped.SourceJson, StringComparison.Ordinal);
        Assert.Contains(mapped.Notes, n => n.Contains("site id", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Map_PreservesWebHostingStore_AndMatchesInstallerCertStore()
    {
        var root = new JsonObject
        {
            ["Id"] = "wh",
            ["LastFriendlyName"] = "[IIS] Site, (any host)",
            ["TargetPluginOptions"] = new JsonObject { ["SiteId"] = 3, ["CommonName"] = "site.example.com" },
            ["StorePluginOptions"] = new JsonArray(new JsonObject { ["StoreName"] = "WebHosting" }),
            ["InstallationPluginOptions"] = new JsonArray(
                new JsonObject { ["Plugin"] = "ea6a5be3-f8de-4d27-a6bd-750b619b2ee2" }),
        };
        var renewal = new WinAcmeRenewal("C:\\fake\\wh.renewal.json", root);
        var ctx = new WinAcmeMapContext(ResolveSiteName: _ => "Site");

        var mapped = WinAcmeMapper.Map(renewal, index: 0, ctx);

        // win-acme's WebHosting store must survive, and the installer must bind from it.
        Assert.Contains("\"storeName\":\"WebHosting\"", mapped.StoresJson, StringComparison.Ordinal);
        Assert.Contains("\"certStoreName\":\"WebHosting\"", mapped.InstallationsJson, StringComparison.Ordinal);
    }

    [Fact]
    public void Map_CertStoreOverride_WinsOverWinAcmesStore_AndMatchesInstaller()
    {
        var root = new JsonObject
        {
            ["Id"] = "ov",
            ["LastFriendlyName"] = "[IIS] Site, (any host)",
            ["TargetPluginOptions"] = new JsonObject { ["SiteId"] = 4, ["CommonName"] = "site.example.com" },
            ["StorePluginOptions"] = new JsonArray(new JsonObject { ["StoreName"] = "My" }), // win-acme said My
            ["InstallationPluginOptions"] = new JsonArray(
                new JsonObject { ["Plugin"] = "ea6a5be3-f8de-4d27-a6bd-750b619b2ee2" }),
        };
        var renewal = new WinAcmeRenewal("C:\\fake\\ov.renewal.json", root);
        var ctx = new WinAcmeMapContext(
            ResolveSiteName: _ => "Site", CertStoreName: "WebHosting", CertStoreLocation: "LocalMachine");

        var mapped = WinAcmeMapper.Map(renewal, index: 0, ctx);

        Assert.Contains("\"storeName\":\"WebHosting\"", mapped.StoresJson, StringComparison.Ordinal);
        Assert.Contains("\"certStoreName\":\"WebHosting\"", mapped.InstallationsJson, StringComparison.Ordinal);
    }

    [Fact]
    public void Map_InstallStepOwnSiteId_WinsOverTargetSite()
    {
        var root = new JsonObject
        {
            ["Id"] = "xyz",
            ["LastFriendlyName"] = "two-sites",
            ["TargetPluginOptions"] = new JsonObject { ["SiteId"] = 1 },
            ["InstallationPluginOptions"] = new JsonArray(new JsonObject { ["SiteId"] = "2" }),
        };
        var renewal = new WinAcmeRenewal("C:\\fake\\xyz.renewal.json", root);
        var ctx = new WinAcmeMapContext(
            ResolveSiteName: id => id switch { "1" => "Site One", "2" => "Site Two", _ => null });

        var mapped = WinAcmeMapper.Map(renewal, index: 0, ctx);

        Assert.Contains("\"siteName\":\"Site One\"", mapped.SourceJson, StringComparison.Ordinal);
        Assert.Contains("\"siteName\":\"Site Two\"", mapped.InstallationsJson, StringComparison.Ordinal);
    }

    [Fact]
    public void Map_Azure_ReferencesExistingSecret_AndImportsNoSecret()
    {
        var ctx = new WinAcmeMapContext(AzureSecretName: "Azure");

        var mapped = WinAcmeMapper.Map(AzureValidationRenewal(), index: 0, ctx);

        Assert.Contains("\"clientSecretSecretName\":\"Azure\"", mapped.ValidationJson, StringComparison.Ordinal);
        Assert.Empty(mapped.Secrets); // win-acme's secret is never carried over
        Assert.DoesNotContain("winacme-azure", mapped.ValidationJson, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Map_Azure_WithoutChosenSecret_LeavesItBlank_AndNotes()
    {
        var mapped = WinAcmeMapper.Map(AzureValidationRenewal(), index: 0, context: null);

        Assert.Contains("\"clientSecretSecretName\":\"\"", mapped.ValidationJson, StringComparison.Ordinal);
        Assert.Empty(mapped.Secrets);
        Assert.Contains(mapped.Notes, n => n.Contains("client-secret", StringComparison.OrdinalIgnoreCase));
    }
}