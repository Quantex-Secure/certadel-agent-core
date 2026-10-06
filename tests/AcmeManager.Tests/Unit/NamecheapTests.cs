using AcmeManager.Plugins.BuiltIn.Validation;

namespace AcmeManager.Tests.Unit;

public sealed class NamecheapTests
{
    private const string GetHostsOk = """
        <?xml version="1.0" encoding="utf-8"?>
        <ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
          <Errors />
          <CommandResponse Type="namecheap.domains.dns.getHosts">
            <DomainDNSGetHostsResult Domain="contoso.com" EmailType="MX" IsUsingOurDNS="true">
              <host HostId="1" Name="@" Type="A" Address="1.2.3.4" MXPref="10" TTL="1800" />
              <host HostId="2" Name="www" Type="CNAME" Address="example.com." MXPref="10" TTL="1800" />
            </DomainDNSGetHostsResult>
          </CommandResponse>
        </ApiResponse>
        """;

    [Fact]
    public void ParseHosts_ReadsAllRecords_AndEmailType()
    {
        var result = NamecheapDnsClient.ParseHosts(GetHostsOk);

        Assert.Equal("MX", result.EmailType); // must be preserved on setHosts or email routing resets
        Assert.Equal(2, result.Hosts.Count);
        Assert.Contains(result.Hosts, h => h is { Name: "@", Type: "A", Address: "1.2.3.4" });
        Assert.Contains(result.Hosts, h => h is { Name: "www", Type: "CNAME" });
    }

    [Fact]
    public void ParseHosts_ThrowsOnApiError()
    {
        const string error = """
            <ApiResponse Status="ERROR" xmlns="http://api.namecheap.com/xml.response">
              <Errors><Error Number="1011102">API Key is invalid or API access has not been enabled</Error></Errors>
            </ApiResponse>
            """;

        var ex = Assert.Throws<InvalidOperationException>(() => NamecheapDnsClient.ParseHosts(error));
        Assert.Contains("API Key is invalid", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildSetHostsForm_ReSendsEveryRecord_PlusEmailType()
    {
        // setHosts REPLACES all records — the form must carry every existing host
        // (so we don't wipe DNS) + the new challenge TXT, and EmailType.
        var existing = NamecheapDnsClient.ParseHosts(GetHostsOk);
        var withTxt = existing with
        {
            Hosts = [.. existing.Hosts, new NamecheapHost("_acme-challenge", "TXT", "the-digest", 10, 60)],
        };

        var form = NamecheapDnsClient.BuildSetHostsForm("contoso", "com", withTxt);

        Assert.Equal("contoso", form["SLD"]);
        Assert.Equal("com", form["TLD"]);
        Assert.Equal("MX", form["EmailType"]);
        // 3 records, 1-indexed.
        Assert.Equal("@", form["HostName1"]);
        Assert.Equal("CNAME", form["RecordType2"]);
        Assert.Equal("_acme-challenge", form["HostName3"]);
        Assert.Equal("TXT", form["RecordType3"]);
        Assert.Equal("the-digest", form["Address3"]);
    }

    [Theory]
    [InlineData("_acme-challenge.www.contoso.com", "contoso", "com", "_acme-challenge.www")]
    [InlineData("_acme-challenge.example.com", "example", "com", "_acme-challenge")]
    public void SplitDomain_DerivesSldTldHost(string fqdn, string sld, string tld, string host)
    {
        var (s, t, h) = NamecheapDns01Validator.SplitDomain(fqdn);

        Assert.Equal(sld, s);
        Assert.Equal(tld, t);
        Assert.Equal(host, h);
    }
}