using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AcmeManager.Service.Coverage;

namespace AcmeManager.Tests.Unit;

public sealed class CoverageTests
{
    [Fact]
    public void Reconcile_CarriesIssuerThrough()
    {
        var served = new ServedCertInfo("/etc/haproxy/certs/x.pem", ["x.com"], Now.AddDays(30), null, Issuer: "Let's Encrypt");

        var entry = CoverageService.Reconcile(served, Now, Empty, Empty, Empty, "acme.sh");

        Assert.Equal("Let's Encrypt", entry.Issuer);
    }

    [Fact]
    public void Reconcile_MissingCert_WhenBindingPointsAtAbsentCert()
    {
        // A known thumbprint (the binding) but the cert is gone from the store — broken,
        // not a benign parse error.
        var served = new ServedCertInfo("IIS: Site @ x [My]", [], null,
            "Bound cert AF9CCE not found in My store", Thumbprint: "AF9CCE");

        var entry = CoverageService.Reconcile(served, Now, Empty, Empty, Empty, "win-acme");

        Assert.Equal(CoverageStatus.MissingCert, entry.Status);
    }

    [Fact]
    public void ExtractIssuer_DetectsSelfSigned()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=test.local", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        Assert.Equal("self-signed", ServedCertReader.ExtractIssuer(cert));
    }

    private const string HaProxyCfg = """
        frontend http_frontend
            bind *:80
            http-request redirect scheme https code 301

        frontend https_terminated
            bind 127.0.0.1:8443 ssl crt /etc/haproxy/certs/ accept-proxy
            # crt /etc/haproxy/old/ -- commented, must be ignored
            mode http
        """;

    [Fact]
    public void ParseCertSources_FindsCrtDir_IgnoresComments()
    {
        var sources = HaProxyConfig.ParseCertSources(HaProxyCfg);

        Assert.Equal(["/etc/haproxy/certs/"], sources);
    }

    [Fact]
    public void ParseCertSources_HandlesCrtListAndDedup()
    {
        var sources = HaProxyConfig.ParseCertSources(
            "bind :443 ssl crt /a/x.pem\nbind :443 ssl crt /a/x.pem\nbind :8443 ssl crt-list /etc/haproxy/list.txt");

        Assert.Equal(["/a/x.pem", "/etc/haproxy/list.txt"], sources);
    }

    private static readonly DateTimeOffset Now = new(2026, 6, 10, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Reconcile_Managed_WhenAnAgentRenewalCoversADomain()
    {
        var served = new ServedCertInfo("/etc/haproxy/certs/fabrikam.com.pem",
            ["fabrikam.com", "www.fabrikam.com"], Now.AddDays(60), null);
        var agent = new Dictionary<string, string> { ["fabrikam.com"] = "fabrikam.com" };

        var entry = CoverageService.Reconcile(served, Now, Empty, agent, Empty, "acme.sh");

        Assert.Equal(CoverageStatus.Managed, entry.Status);
        Assert.Equal(60, entry.DaysUntilExpiry);
    }

    [Fact]
    public void Reconcile_Managed_ByThumbprint_EvenWhenNoDomainMatches()
    {
        // The win2019iis case: an IIS-source renewal stores no identifiers, so domain
        // matching misses it — but the served cert's thumbprint is one we issued.
        var served = new ServedCertInfo("IIS: Games @ blockdrop.example.com [WebHosting]",
            ["blockdrop.example.com"], Now.AddDays(40), null, "ABC123THUMB");
        // The real loader keys this map OrdinalIgnoreCase; lowercase here vs uppercase served proves it.
        var thumbs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["abc123thumb"] = "blockdrop" };

        var entry = CoverageService.Reconcile(served, Now, thumbs, Empty, Empty, "win-acme");

        Assert.Equal(CoverageStatus.Managed, entry.Status);
        Assert.Contains("blockdrop", entry.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Reconcile_Managed_ByThumbprint_EvenWhenCertUnreadable()
    {
        // Thumbprint known from the IIS binding, but the cert wasn't readable from the
        // store — still managed if we issued that thumbprint.
        var served = new ServedCertInfo("IIS: Site @ x [My]", [], null, "not found in store", "DEADBEEF");
        var thumbs = new Dictionary<string, string> { ["DEADBEEF"] = "x-renewal" };

        var entry = CoverageService.Reconcile(served, Now, thumbs, Empty, Empty, "win-acme");

        Assert.Equal(CoverageStatus.Managed, entry.Status);
    }

    [Fact]
    public void Reconcile_OtherTool_WhenOnlyTheOtherToolRenewsIt()
    {
        var served = new ServedCertInfo("/etc/haproxy/certs/mail.contoso.com.pem",
            ["mail.contoso.com"], Now.AddDays(30), null);
        var otherTool = new Dictionary<string, string> { ["mail.contoso.com"] = "/home/admin/.acme.sh" };

        var entry = CoverageService.Reconcile(served, Now, Empty, Empty, otherTool, "acme.sh");

        Assert.Equal(CoverageStatus.OtherTool, entry.Status);
        Assert.Contains("acme.sh", entry.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Reconcile_Unmanaged_WhenNothingRenewsIt()
    {
        var served = new ServedCertInfo("/etc/haproxy/certs/orphan.example.com.pem",
            ["orphan.example.com"], Now.AddDays(5), null);

        var entry = CoverageService.Reconcile(served, Now, Empty, Empty, Empty, "acme.sh");

        Assert.Equal(CoverageStatus.Unmanaged, entry.Status);
        Assert.Equal(5, entry.DaysUntilExpiry);
    }

    [Fact]
    public void Reconcile_Unreadable_WhenTheFileIsntACert()
    {
        var served = new ServedCertInfo("/etc/haproxy/certs/notacert.pem", [], null, "no certificate found");

        var entry = CoverageService.Reconcile(served, Now, Empty, Empty, Empty, "acme.sh");

        Assert.Equal(CoverageStatus.Unreadable, entry.Status);
    }

    private static readonly IReadOnlyDictionary<string, string> Empty =
        new Dictionary<string, string>();
}