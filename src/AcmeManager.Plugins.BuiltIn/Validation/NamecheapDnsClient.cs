using System.Xml.Linq;

namespace AcmeManager.Plugins.BuiltIn.Validation;

/// <summary>One Namecheap host record (relative name, e.g. "@", "www", "_acme-challenge").</summary>
internal sealed record NamecheapHost(string Name, string Type, string Address, int MxPref, int Ttl);

/// <summary>getHosts result: every record plus the domain's email-routing type
/// (both must be re-sent on setHosts, which REPLACES all records).</summary>
internal sealed record NamecheapHosts(IReadOnlyList<NamecheapHost> Hosts, string EmailType);

/// <summary>
/// Minimal Namecheap DNS API client (XML at api.namecheap.com). The crucial
/// detail: <c>setHosts</c> is a full replace, so callers read all hosts, add/remove
/// the one record, and write them ALL back — preserving the email-routing type too.
/// XML parsing/form-building are static + testable; the network calls are thin.
/// </summary>
internal sealed class NamecheapDnsClient(
    HttpClient http, string apiUser, string userName, string apiKey, string clientIp, bool sandbox)
{
    private static readonly XNamespace Ns = "http://api.namecheap.com/xml.response";

    private string BaseUrl => sandbox
        ? "https://api.sandbox.namecheap.com/xml.response"
        : "https://api.namecheap.com/xml.response";

    public async Task<NamecheapHosts> GetHostsAsync(string sld, string tld, CancellationToken ct)
    {
        var url = $"{BaseUrl}?{Common("namecheap.domains.dns.getHosts")}" +
            $"&SLD={Uri.EscapeDataString(sld)}&TLD={Uri.EscapeDataString(tld)}";
        using var resp = await http.GetAsync(url, ct);
        resp.EnsureSuccessStatusCode();
        return ParseHosts(await resp.Content.ReadAsStringAsync(ct));
    }

    public async Task SetHostsAsync(string sld, string tld, NamecheapHosts hosts, CancellationToken ct)
    {
        var form = BuildSetHostsForm(sld, tld, hosts);
        form["ApiUser"] = apiUser;
        form["UserName"] = userName;
        form["ApiKey"] = apiKey;
        form["ClientIp"] = clientIp;
        form["Command"] = "namecheap.domains.dns.setHosts";

        using var content = new FormUrlEncodedContent(form);
        using var resp = await http.PostAsync(BaseUrl, content, ct);
        resp.EnsureSuccessStatusCode();
        EnsureOk(XDocument.Parse(await resp.Content.ReadAsStringAsync(ct)));
    }

    private string Common(string command) =>
        $"ApiUser={Uri.EscapeDataString(apiUser)}&UserName={Uri.EscapeDataString(userName)}" +
        $"&ApiKey={Uri.EscapeDataString(apiKey)}&ClientIp={Uri.EscapeDataString(clientIp)}&Command={command}";

    internal static NamecheapHosts ParseHosts(string xml)
    {
        var doc = XDocument.Parse(xml);
        EnsureOk(doc);
        var result = doc.Descendants(Ns + "DomainDNSGetHostsResult").FirstOrDefault();
        var emailType = (string?)result?.Attribute("EmailType") ?? "NONE";
        var hosts = doc.Descendants(Ns + "host").Select(h => new NamecheapHost(
            (string?)h.Attribute("Name") ?? "",
            (string?)h.Attribute("Type") ?? "",
            (string?)h.Attribute("Address") ?? "",
            int.TryParse((string?)h.Attribute("MXPref"), out var mx) ? mx : 10,
            int.TryParse((string?)h.Attribute("TTL"), out var ttl) ? ttl : 1800)).ToList();
        return new NamecheapHosts(hosts, emailType);
    }

    internal static Dictionary<string, string> BuildSetHostsForm(string sld, string tld, NamecheapHosts hosts)
    {
        var form = new Dictionary<string, string>
        {
            ["SLD"] = sld,
            ["TLD"] = tld,
            ["EmailType"] = hosts.EmailType, // preserve email routing — omitting it can reset MX handling
        };
        for (var i = 0; i < hosts.Hosts.Count; i++)
        {
            var n = i + 1;
            var h = hosts.Hosts[i];
            form[$"HostName{n}"] = h.Name;
            form[$"RecordType{n}"] = h.Type;
            form[$"Address{n}"] = h.Address;
            form[$"MXPref{n}"] = h.MxPref.ToString();
            form[$"TTL{n}"] = h.Ttl.ToString();
        }
        return form;
    }

    private static void EnsureOk(XDocument doc)
    {
        if (!string.Equals((string?)doc.Root?.Attribute("Status"), "OK", StringComparison.OrdinalIgnoreCase))
        {
            var err = doc.Descendants(Ns + "Error").Select(e => e.Value).FirstOrDefault() ?? "unknown error";
            throw new InvalidOperationException($"Namecheap API error: {err}");
        }
    }
}