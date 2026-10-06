using AcmeManager.Plugins.Contracts.Sources;
using AcmeManager.Plugins.Contracts.Storage;
using AcmeManager.Plugins.Iis;

using Microsoft.Extensions.Logging.Abstractions;

namespace AcmeManager.Tests.Unit;

public sealed class IisPluginHardeningTests
{
    // ---------------- IisSource: empty site filter ----------------

    [Fact]
    public async Task IisSource_WithNoSiteNameAndNoAllSites_FailsFast()
    {
        var source = new IisSource(NullLogger<IisSource>.Instance);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await source.ResolveAsync(new SourceContext(new IisSourceOptions()), default));

        Assert.Contains("no site name", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ---------------- IisSource: host filtering ----------------

    [Fact]
    public void FilterHosts_NoFilters_KeepsEverything()
    {
        var hosts = new[] { "a.example.com", "b.example.com" };

        var result = IisSource.FilterHosts(hosts, [], []);

        Assert.Equal(hosts, result);
    }

    [Fact]
    public void FilterHosts_ExcludesExactHost_CaseInsensitively()
    {
        var result = IisSource.FilterHosts(
            ["blockdrop.example.com", "northwind.net"],
            includeHosts: [],
            excludeHosts: ["NORTHWIND.NET"]);

        Assert.Equal(["blockdrop.example.com"], result);
    }

    [Fact]
    public void FilterHosts_WildcardMatchesSubdomains_NotTheApex()
    {
        var result = IisSource.FilterHosts(
            ["example.com", "blockdrop.example.com", "other.net"],
            includeHosts: ["*.example.com"],
            excludeHosts: []);

        Assert.Equal(["blockdrop.example.com"], result);
    }

    [Fact]
    public void FilterHosts_ExcludeWinsOverInclude()
    {
        var result = IisSource.FilterHosts(
            ["a.example.com", "b.example.com"],
            includeHosts: ["*.example.com"],
            excludeHosts: ["b.example.com"]);

        Assert.Equal(["a.example.com"], result);
    }

    // ---------------- IisInstaller: binding host resolution ----------------

    private static CertificateBundle Bundle(string commonName) => new(
        CommonName: commonName,
        SubjectAlternativeNames: [commonName],
        PfxBytes: [1],
        PfxPassword: "",
        NotBefore: DateTimeOffset.UtcNow,
        NotAfter: DateTimeOffset.UtcNow.AddDays(90),
        Thumbprint: "AA00");

    private static CertificateBundle BundleWith(string commonName, params string[] sans) => new(
        CommonName: commonName,
        SubjectAlternativeNames: sans,
        PfxBytes: [1],
        PfxPassword: "",
        NotBefore: DateTimeOffset.UtcNow,
        NotAfter: DateTimeOffset.UtcNow.AddDays(90),
        Thumbprint: "AA00");

    [Fact]
    public void SelectTargets_BindsEveryBindingWhoseHostIsACertName()
    {
        // One cert with three SANs → binds the three matching bindings, leaves others.
        var certNames = IisInstaller.CertNames(BundleWith("test.example.com", "test.example.com", "test1.example.com", "test2.example.com"));
        BindingTarget[] existing =
        [
            new("Default Web Site", "*:443:test.example.com", "test.example.com"),
            new("Default Web Site", "*:443:test1.example.com", "test1.example.com"),
            new("Default Web Site", "*:443:test2.example.com", "test2.example.com"),
            new("Other Site", "*:443:unrelated.com", "unrelated.com"),
        ];

        var targets = IisInstaller.SelectTargets(certNames, existing, "", "*", 443, "Default Web Site", true, "test.example.com");

        Assert.Equal(["test.example.com", "test1.example.com", "test2.example.com"],
            targets.Select(t => t.Host).OrderBy(h => h, StringComparer.Ordinal));
        Assert.DoesNotContain(targets, t => t.Host == "unrelated.com");
    }

    [Fact]
    public void SelectTargets_TwoCertsOnOneSite_EachClaimsOnlyItsOwnNames()
    {
        BindingTarget[] existing =
        [
            new("S", "*:443:test", "test"),
            new("S", "*:443:test1", "test1"),
            new("S", "*:443:test2", "test2"),
        ];

        var certA = IisInstaller.SelectTargets(IisInstaller.CertNames(BundleWith("test", "test", "test1")), existing, "", "*", 443, "S", true, "test");
        var certB = IisInstaller.SelectTargets(IisInstaller.CertNames(BundleWith("test2", "test2")), existing, "", "*", 443, "S", true, "test2");

        Assert.Equal(["test", "test1"], certA.Select(t => t.Host).OrderBy(h => h, StringComparer.Ordinal));
        Assert.Equal(["test2"], certB.Select(t => t.Host));
    }

    [Fact]
    public void SelectTargets_FallsBackToCommonName_WhenNothingMatches()
    {
        var certNames = IisInstaller.CertNames(BundleWith("new.example.com", "new.example.com"));

        var targets = IisInstaller.SelectTargets(certNames, [], "", "*", 443, "Default Web Site", true, "new.example.com");

        Assert.Single(targets);
        Assert.Equal("*:443:new.example.com", targets[0].BindingInfo);
    }

    [Fact]
    public void SelectTargets_Empty_WhenNoSiteNoMatchNoHost()
    {
        // No site, no existing binding to match, no explicit host → nothing to bind.
        // InstallAsync no-ops gracefully here (cert is stored; binds on a later run once
        // a matching binding exists) — pre-placing a cert before its site is valid.
        var certNames = IisInstaller.CertNames(BundleWith("new.example.com", "new.example.com"));

        var targets = IisInstaller.SelectTargets(certNames, [], "", "*", 443, siteName: "", requireSni: true, commonName: "new.example.com");

        Assert.Empty(targets);
    }

    [Fact]
    public void SelectTargets_EnsuresExplicitHost_EvenWhenNoBindingExists()
    {
        var certNames = IisInstaller.CertNames(BundleWith("cn.example.com", "cn.example.com"));

        var targets = IisInstaller.SelectTargets(certNames, [], "explicit.example.com", "*", 443, "Site", true, "cn.example.com");

        Assert.Contains(targets, t => t.BindingInfo == "*:443:explicit.example.com");
    }

    [Theory]
    [InlineData("*:443:test.example.com", "test.example.com")]
    [InlineData("*:443:", "")]
    public void BindingHost_ParsesHostFromBindingInformation(string info, string expected) =>
        Assert.Equal(expected, IisInstaller.BindingHost(info));
}