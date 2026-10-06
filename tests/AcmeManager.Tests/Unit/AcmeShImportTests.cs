using System.Text.Json.Nodes;

using AcmeManager.Service.Migration.AcmeSh;

namespace AcmeManager.Tests.Unit;

public sealed class AcmeShImportTests
{
    // A real-world acme.sh domain .conf (reload cmd base64 = "bash /etc/haproxy/deploy-cert.sh example.com").
    private const string ExampleConf = """
        Le_Domain='example.com'
        Le_Alt='no'
        Le_Webroot='dns_azure'
        Le_API='https://acme-v02.api.letsencrypt.org/directory'
        Le_Keylength='2048'
        Le_ReloadCmd='__ACME_BASE64__START_YmFzaCAvZXRjL2hhcHJveHkvZGVwbG95LWNlcnQuc2ggZXhhbXBsZS5jb20=__ACME_BASE64__END_'
        Le_RealFullChainPath=''
        """;

    [Fact]
    public void Parse_ReadsLeVars_DecodesReload_AndTreatsAltNoAsEmpty()
    {
        var conf = AcmeShConf.Parse(ExampleConf, "/root/.acme.sh/example.com/example.com.conf");

        Assert.Equal("example.com", conf.Domain);
        Assert.Empty(conf.AltNames); // Le_Alt='no' means no SANs
        Assert.Equal("dns_azure", conf.ValidationMethod);
        Assert.Equal("https://acme-v02.api.letsencrypt.org/directory", conf.DirectoryUrl);
        Assert.Equal("bash /etc/haproxy/deploy-cert.sh example.com", conf.ReloadCommand);
    }

    [Fact]
    public void Parse_SplitsAltNames()
    {
        var conf = AcmeShConf.Parse("Le_Domain='example.com'\nLe_Alt='www.example.com,cdn.example.com'", "x");

        Assert.Equal(["www.example.com", "cdn.example.com"], conf.AltNames);
    }

    [Fact]
    public void Map_SnapshotsSelectedDnsProviderProfile_ForTheCertsMethod()
    {
        var conf = AcmeShConf.Parse(ExampleConf, "x"); // dns_azure
        const string profileOptions =
            """{"tenantId":"tid","subscriptionId":"sid","clientSecretSecretName":"azure-dns","zoneName":"example.com"}""";
        var ctx = new AcmeShMapContext(
            DnsProfile: new DnsProfileSnapshot("validation.dns-01.azure", profileOptions));

        var mapped = AcmeShMapper.Map(conf, ctx);

        var source = JsonNode.Parse(mapped.SourceJson)!;
        Assert.Equal("source.manual", source["pluginId"]!.ToString());
        Assert.Contains("example.com", source["options"]!["identifiers"]!.AsArray().Select(n => n!.ToString()));

        // Validation = the profile's plugin + its options VERBATIM (secret reference and all).
        var validation = JsonNode.Parse(mapped.ValidationJson)!;
        Assert.Equal("validation.dns-01.azure", validation["pluginId"]!.ToString());
        Assert.Equal("tid", validation["options"]!["tenantId"]!.ToString());
        Assert.Equal("azure-dns", validation["options"]!["clientSecretSecretName"]!.ToString());

        var installer = JsonNode.Parse(mapped.InstallationsJson)!.AsArray()[0]!;
        Assert.Equal("installer.haproxy", installer["pluginId"]!.ToString());
        Assert.Equal("/etc/haproxy/certs/example.com.pem", installer["options"]!["pemPath"]!.ToString());
    }

    [Fact]
    public void Map_NoProfileSelectedForMethod_FallsBackToManualDns()
    {
        var conf = AcmeShConf.Parse(ExampleConf, "x"); // dns_azure, but nothing selected
        var mapped = AcmeShMapper.Map(conf, new AcmeShMapContext());

        var validation = JsonNode.Parse(mapped.ValidationJson)!;
        Assert.Equal("validation.dns-01.manual", validation["pluginId"]!.ToString());
        Assert.NotEmpty(mapped.Notes);
    }

    [Fact]
    public void Map_PemStore_WhenSelected()
    {
        var conf = AcmeShConf.Parse(ExampleConf, "x");
        var ctx = new AcmeShMapContext(StorePluginId: "store.pem");

        var store = JsonNode.Parse(AcmeShMapper.Map(conf, ctx).StoresJson)!.AsArray()[0]!;
        Assert.Equal("store.pem", store["pluginId"]!.ToString());
        Assert.Equal("example.com", store["options"]!["baseName"]!.ToString());
    }


    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("alienassault.example.com", "example.com")]
    [InlineData("a.b.example.org", "example.org")]
    public void RegistrableDomain_TakesLastTwoLabels(string input, string expected) =>
        Assert.Equal(expected, AcmeShMapper.RegistrableDomain(input));

    [Fact]
    public void ReadRenewals_FindsConfByContent_HandlesEcc_SkipsCsrConf()
    {
        var home = Path.Combine(Path.GetTempPath(), $"acmesh-{Guid.NewGuid():N}");
        try
        {
            // RSA cert: <domain>/<domain>.conf — plus a .csr.conf that must be ignored.
            WriteConf(home, "rsa.test", "rsa.test.conf", "Le_Domain='rsa.test'\nLe_Webroot='dns_azure'");
            File.WriteAllText(Path.Combine(home, "rsa.test", "rsa.test.csr.conf"), "[req]\ndefault_bits = 2048");
            // EC cert: dir is <domain>_ecc but the conf is <domain>.conf.
            WriteConf(home, "ecc.test_ecc", "ecc.test.conf", "Le_Domain='ecc.test'\nLe_Webroot='dns_azure'");
            // acme.sh internals that must be skipped.
            Directory.CreateDirectory(Path.Combine(home, "ca"));

            var renewals = AcmeShReader.ReadRenewals([home]);

            Assert.Equal(2, renewals.Count);
            Assert.Contains(renewals, r => r.Domain == "rsa.test");
            Assert.Contains(renewals, r => r.Domain == "ecc.test"); // _ecc dir is found
        }
        finally
        {
            Directory.Delete(home, recursive: true);
        }
    }

    private static void WriteConf(string home, string dir, string confName, string content)
    {
        var d = Path.Combine(home, dir);
        Directory.CreateDirectory(d);
        File.WriteAllText(Path.Combine(d, confName), content);
    }

    [Fact]
    public void Map_WebrootPath_MapsToFilesystemHttp01()
    {
        var conf = AcmeShConf.Parse("Le_Domain='x.test'\nLe_Webroot='/var/www/html'", "x");

        var mapped = AcmeShMapper.Map(conf, new AcmeShMapContext());

        var validation = JsonNode.Parse(mapped.ValidationJson)!;
        Assert.Equal("validation.http-01.filesystem", validation["pluginId"]!.ToString());
        Assert.Equal("/var/www/html", validation["options"]!["webRootPath"]!.ToString());
    }
}