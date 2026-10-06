using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Web;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Installation;
using AcmeManager.Plugins.Contracts.Storage;
using AcmeManager.Plugins.Linux.Synology;

using Microsoft.Extensions.Logging.Abstractions;

namespace AcmeManager.Tests.Unit;

public sealed class DsmInstallerTests
{
    private const string Account = @"EXAMPLE\admin";
    private const string Password = "pw";

    // ---------------- Fake DSM ----------------

    private sealed class FakeCert
    {
        public required string Id { get; init; }
        public string Desc { get; set; } = "";
        public bool IsDefault { get; set; }
        public string CommonName { get; set; } = "synology";
        public DateTimeOffset ValidTill { get; set; } = DateTimeOffset.UnixEpoch.AddYears(60);
        public List<JsonObject> Services { get; } = [];
        public string? KeyPem { get; set; }
        public string? ChainPem { get; set; }
    }

    /// <summary>A stateful stand-in for DSM's Web API: login, CRT list, import
    /// (create or replace by id), Service set, logout.</summary>
    private sealed class FakeDsm : HttpMessageHandler
    {
        private int _nextId = 1;
        private int _nextSid = 1;
        private readonly HashSet<string> _validSids = [];

        public List<FakeCert> Certs { get; } = [];
        public List<string> Calls { get; } = [];
        public List<Dictionary<string, string>> Imports { get; } = [];
        public bool DropConnectionAfterImport { get; set; }
        public bool EndSessionDuringImport { get; set; }
        public bool EndSessionAfterImport { get; set; }
        public int Logins { get; private set; }
        public int ServiceSetCalls { get; private set; }

        public static JsonObject Service(string displayName, string service, string subscriber) => new()
        {
            ["display_name"] = displayName,
            ["service"] = service,
            ["subscriber"] = subscriber,
            ["isPkg"] = false,
            ["owner"] = "root",
            ["multiple_cert"] = true,
            ["user_setable"] = true,
        };

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
        {
            if (req.RequestUri!.AbsolutePath.EndsWith("query.cgi", StringComparison.Ordinal))
            {
                return Json("""{"data":{"SYNO.API.Auth":{"path":"entry.cgi","maxVersion":7}},"success":true}""");
            }

            if (req.RequestUri.Query.Contains("method=import", StringComparison.Ordinal))
            {
                return await ImportAsync(req, ct);
            }

            var form = HttpUtility.ParseQueryString(await req.Content!.ReadAsStringAsync(ct));
            var call = $"{form["api"]}.{form["method"]}";
            Calls.Add(call);
            if (call == "SYNO.API.Auth.login")
            {
                return form["account"] == Account && form["passwd"] == Password ? Login() : Error(400);
            }
            if (!_validSids.Contains(form["_sid"] ?? ""))
            {
                return Error(119);
            }
            return call switch
            {
                "SYNO.API.Auth.logout" => Json("""{"success":true}"""),
                "SYNO.Core.Certificate.CRT.list" => Json(ListJson()),
                "SYNO.Core.Certificate.Service.set" => SetServices(form["settings"]!),
                _ => Error(103),
            };
        }

        private HttpResponseMessage Login()
        {
            Logins++;
            var sid = $"SID{_nextSid++}";
            _validSids.Add(sid);
            return Json($$"""{"data":{"sid":"{{sid}}","synotoken":"TOK"},"success":true}""");
        }

        private static HttpResponseMessage Error(int code) =>
            Json($$"""{"error":{"code":{{code}}},"success":false}""");

        private async Task<HttpResponseMessage> ImportAsync(HttpRequestMessage req, CancellationToken ct)
        {
            var query = HttpUtility.ParseQueryString(req.RequestUri!.Query);
            Calls.Add($"{query["api"]}.{query["method"]}");
            if (!_validSids.Contains(query["_sid"] ?? ""))
            {
                return Error(119);
            }

            var parts = ParseStrictMultipart(req.Content!, await req.Content!.ReadAsStringAsync(ct));
            Imports.Add(parts);

            using var leaf = X509Certificate2.CreateFromPem(parts["cert"]);
            var id = parts.GetValueOrDefault("id") ?? "";
            var cert = id.Length > 0 ? Certs.Single(c => c.Id == id) : NewCert();
            cert.Desc = parts.GetValueOrDefault("desc") ?? "";
            cert.CommonName = leaf.GetNameInfo(X509NameType.DnsName, forIssuer: false);
            cert.ValidTill = new DateTimeOffset(leaf.NotAfter.ToUniversalTime(), TimeSpan.Zero);
            cert.KeyPem = parts["key"];
            cert.ChainPem = parts.GetValueOrDefault("inter_cert");
            if (parts.GetValueOrDefault("as_default") == "true")
            {
                Certs.ForEach(c => c.IsDefault = false);
                cert.IsDefault = true;
            }

            if (DropConnectionAfterImport)
            {
                DropConnectionAfterImport = false;
                throw new HttpRequestException("connection reset (nginx restarting)");
            }
            if (EndSessionDuringImport || EndSessionAfterImport)
            {
                _validSids.Clear();
                if (EndSessionDuringImport)
                {
                    EndSessionDuringImport = false;
                    return Error(119);
                }
                EndSessionAfterImport = false;
            }
            return Json($$"""{"data":{"id":"{{cert.Id}}","restart_httpd":true},"success":true}""");
        }

        /// <summary>
        /// Parses the upload the way DSM's CGI parser tolerates it — the exact shape
        /// acme.sh sends: an unquoted boundary, quoted name/filename, no RFC 5987
        /// <c>filename*</c>, file parts typed application/octet-stream and text parts
        /// untyped. (DSM answered error 108 to .NET's default multipart encoding.)
        /// </summary>
        private static Dictionary<string, string> ParseStrictMultipart(HttpContent content, string body)
        {
            var contentType = content.Headers.NonValidated["Content-Type"].ToString();
            Assert.Matches(@"^multipart/form-data; boundary=[^"";\s]+$", contentType);
            var boundary = contentType["multipart/form-data; boundary=".Length..];
            Assert.EndsWith($"--{boundary}--\r\n", body);

            var parts = new Dictionary<string, string>();
            foreach (var chunk in body.Split($"--{boundary}").Skip(1).SkipLast(1))
            {
                Assert.StartsWith("\r\n", chunk);
                Assert.EndsWith("\r\n", chunk);
                var text = chunk[2..^2];
                var split = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                var headers = text[..split].Split("\r\n");
                var match = System.Text.RegularExpressions.Regex.Match(headers[0],
                    "^Content-Disposition: form-data; name=\"([^\"]+)\"(; filename=\"[^\"]+\")?$");
                Assert.True(match.Success, headers[0]);
                if (match.Groups[2].Success)
                {
                    Assert.Equal(["Content-Type: application/octet-stream"], headers[1..]);
                }
                else
                {
                    Assert.Single(headers);
                }
                parts[match.Groups[1].Value] = text[(split + 4)..];
            }
            return parts;
        }

        private FakeCert NewCert()
        {
            var cert = new FakeCert { Id = $"new{_nextId++}" };
            Certs.Add(cert);
            return cert;
        }

        private HttpResponseMessage SetServices(string settingsJson)
        {
            ServiceSetCalls++;
            foreach (var setting in JsonNode.Parse(settingsJson)!.AsArray())
            {
                var service = setting!["service"]!.AsObject();
                var key = (string)service["service"]! + "|" + (string)service["subscriber"]!;
                var from = Certs.Single(c => c.Id == (string)setting["old_id"]!);
                var to = Certs.Single(c => c.Id == (string)setting["id"]!);
                var moved = from.Services.Single(s => (string)s["service"]! + "|" + (string)s["subscriber"]! == key);
                from.Services.Remove(moved);
                to.Services.Add(moved);
            }
            return Json("""{"success":true}""");
        }

        private string ListJson()
        {
            var certs = new JsonArray(Certs.Select(c => (JsonNode)new JsonObject
            {
                ["id"] = c.Id,
                ["desc"] = c.Desc,
                ["is_default"] = c.IsDefault,
                ["subject"] = new JsonObject { ["common_name"] = c.CommonName },
                ["valid_till"] = c.ValidTill.UtcDateTime.ToString("MMM d HH:mm:ss yyyy 'GMT'",
                    System.Globalization.CultureInfo.InvariantCulture),
                ["services"] = new JsonArray(c.Services.Select(s => (JsonNode)s.DeepClone()).ToArray()),
            }).ToArray());
            return new JsonObject { ["success"] = true, ["data"] = new JsonObject { ["certificates"] = certs } }
                .ToJsonString();
        }

        private static HttpResponseMessage Json(string json) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json"),
        };
    }

    private sealed class Secrets : ISecretResolver
    {
        public Task<string> ResolveAsync(string name, CancellationToken ct) =>
            name == "dsm-admin" ? Task.FromResult(Password) : throw new KeyNotFoundException(name);
    }

    // ---------------- Helpers ----------------

    private static FakeDsm DsmWithSystemCert()
    {
        var dsm = new FakeDsm();
        var system = new FakeCert { Id = "sys", IsDefault = true };
        system.Services.Add(FakeDsm.Service("DSM Desktop Service", "default", "system"));
        system.Services.Add(FakeDsm.Service("nas.example.com", "uuid-rp-1", "ReverseProxy"));
        system.Services.Add(FakeDsm.Service("FTPS", "ftpd", "smbftpd"));
        dsm.Certs.Add(system);
        return dsm;
    }

    private static DsmInstaller Installer(FakeDsm dsm) => new(
        new Secrets(),
        NullLogger<DsmInstaller>.Instance,
        endpoint => new DsmApiClient(endpoint, new HttpClient(dsm), ownsHttp: true),
        pollInterval: TimeSpan.Zero);

    private static InstallContext Context(DsmInstallerOptions opts) =>
        new(opts, new Dictionary<string, string>());

    private static DsmInstallerOptions Options(string services = "", string description = "", bool asDefault = false) => new()
    {
        Account = Account,
        PasswordSecretName = "dsm-admin",
        Services = services,
        Description = description,
        AsDefault = asDefault,
    };

    private static CertificateBundle Bundle(string cn, int days = 90)
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootReq = new CertificateRequest("CN=Test Intermediate", rootKey, HashAlgorithmName.SHA256);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var issuer = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafReq = new CertificateRequest($"CN={cn}", leafKey, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(cn);
        leafReq.CertificateExtensions.Add(san.Build());
        var notAfter = DateTimeOffset.UtcNow.AddDays(days);
        notAfter = notAfter.AddTicks(-(notAfter.Ticks % TimeSpan.TicksPerSecond));
        using var signed = leafReq.Create(issuer, DateTimeOffset.UtcNow.AddMinutes(-5), notAfter, RandomNumberGenerator.GetBytes(8));
        using var leaf = signed.CopyWithPrivateKey(leafKey);

        var pfx = new X509Certificate2Collection { leaf, X509CertificateLoader.LoadCertificate(issuer.RawData) }
            .Export(X509ContentType.Pkcs12, "")!;
        return new CertificateBundle(cn, [cn], pfx, "", leaf.NotBefore, notAfter, leaf.Thumbprint);
    }

    // ---------------- Behaviour ----------------

    [Fact]
    public async Task FirstInstall_ImportsNewCert_WithDefaultDescription_AndSplitMaterial()
    {
        var dsm = DsmWithSystemCert();

        var result = await Installer(dsm).InstallAsync(Bundle("nas.test"), Context(Options()), CancellationToken.None);

        Assert.True(result.Applied);
        var imported = Assert.Single(dsm.Certs, c => c.Id != "sys");
        Assert.Equal("Certadel nas.test", imported.Desc);
        Assert.Equal("nas.test", imported.CommonName);
        Assert.Contains("PRIVATE KEY", imported.KeyPem);
        Assert.Contains("Test Intermediate", X509Certificate2.CreateFromPem(imported.ChainPem!).Subject);
        Assert.Equal("", dsm.Imports.Single()["id"]);
        Assert.Equal(0, dsm.ServiceSetCalls);
        Assert.Equal("SYNO.API.Auth.logout", dsm.Calls[^1]);
    }

    [Fact]
    public async Task FirstInstall_BindsRequestedServices_ByDisplayName_CaseInsensitive()
    {
        var dsm = DsmWithSystemCert();

        await Installer(dsm).InstallAsync(Bundle("nas.test"),
            Context(Options(services: "dsm desktop service, NAS.example.com")), CancellationToken.None);

        var imported = dsm.Certs.Single(c => c.Id != "sys");
        Assert.Equal(["DSM Desktop Service", "nas.example.com"],
            imported.Services.Select(s => (string)s["display_name"]!).Order());
        Assert.Equal("FTPS", (string)Assert.Single(dsm.Certs.Single(c => c.Id == "sys").Services)["display_name"]!);
    }

    [Fact]
    public async Task SystemDefault_TheNameDsmsSettingsDialogShows_BindsTheDesktopService()
    {
        var dsm = DsmWithSystemCert();

        var result = await Installer(dsm).InstallAsync(Bundle("nas.test"),
            Context(Options(services: "System default")), CancellationToken.None);

        var imported = dsm.Certs.Single(c => c.Id != "sys");
        Assert.Equal("DSM Desktop Service", (string)Assert.Single(imported.Services)["display_name"]!);
        Assert.Contains("moved DSM Desktop Service", result.Detail);
    }

    [Fact]
    public async Task Result_SaysWhichServicesMoved_AndWhichWereAlreadyBound()
    {
        var dsm = DsmWithSystemCert();
        var installer = Installer(dsm);
        await installer.InstallAsync(Bundle("nas.test"), Context(Options(services: "DSM Desktop Service")), CancellationToken.None);

        var result = await installer.InstallAsync(Bundle("nas.test"),
            Context(Options(services: "DSM Desktop Service, FTPS")), CancellationToken.None);

        Assert.Contains("moved FTPS", result.Detail);
        Assert.Contains("already on it: DSM Desktop Service", result.Detail);
    }

    [Fact]
    public async Task NoServicesRequested_ResultSaysSo_AndListsWhatDsmHas()
    {
        var dsm = DsmWithSystemCert();

        var result = await Installer(dsm).InstallAsync(Bundle("nas.test"), Context(Options()), CancellationToken.None);

        Assert.Contains("no services were moved", result.Detail);
        Assert.Contains("DSM Desktop Service", result.Detail);
        Assert.Contains("nas.example.com", result.Detail);
    }

    [Fact]
    public async Task Asterisk_BindsEveryService()
    {
        var dsm = DsmWithSystemCert();

        await Installer(dsm).InstallAsync(Bundle("nas.test"), Context(Options(services: "*")), CancellationToken.None);

        Assert.Empty(dsm.Certs.Single(c => c.Id == "sys").Services);
        Assert.Equal(3, dsm.Certs.Single(c => c.Id != "sys").Services.Count);
    }

    [Fact]
    public async Task Renewal_ReplacesTheSameDsmCertificate_KeepingIdAndBindings()
    {
        var dsm = DsmWithSystemCert();
        var installer = Installer(dsm);
        var opts = Options(services: "DSM Desktop Service");
        await installer.InstallAsync(Bundle("nas.test", days: 30), Context(opts), CancellationToken.None);
        var id = dsm.Certs.Single(c => c.Id != "sys").Id;
        var renewed = Bundle("nas.test", days: 90);

        var result = await installer.InstallAsync(renewed, Context(opts), CancellationToken.None);

        Assert.True(result.Applied);
        var cert = Assert.Single(dsm.Certs, c => c.Id != "sys");
        Assert.Equal(id, cert.Id);
        Assert.Equal(id, dsm.Imports[^1]["id"]);
        Assert.Equal(renewed.NotAfter, cert.ValidTill);
        Assert.Equal("DSM Desktop Service", (string)Assert.Single(cert.Services)["display_name"]!);
        Assert.Equal(1, dsm.ServiceSetCalls); // only the first install bound anything
    }

    [Fact]
    public async Task AsDefault_MakesTheCertDsmsDefault_AndRenewalKeepsIt()
    {
        var dsm = DsmWithSystemCert();
        var installer = Installer(dsm);

        await installer.InstallAsync(Bundle("nas.test"), Context(Options(asDefault: true)), CancellationToken.None);
        await installer.InstallAsync(Bundle("nas.test"), Context(Options()), CancellationToken.None);

        Assert.True(dsm.Certs.Single(c => c.Id != "sys").IsDefault);
        Assert.All(dsm.Imports, i => Assert.Equal("true", i["as_default"]));
    }

    [Fact]
    public async Task CustomDescription_IsUsedAsTheMatchKey()
    {
        var dsm = DsmWithSystemCert();
        dsm.Certs.Add(new FakeCert { Id = "mine", Desc = "NAS cert" });

        await Installer(dsm).InstallAsync(Bundle("nas.test"), Context(Options(description: "NAS cert")), CancellationToken.None);

        Assert.Equal("mine", dsm.Imports.Single()["id"]);
    }

    [Fact]
    public async Task DuplicateDescriptions_AreRefused_BeforeImporting()
    {
        var dsm = DsmWithSystemCert();
        dsm.Certs.Add(new FakeCert { Id = "a", Desc = "Certadel nas.test" });
        dsm.Certs.Add(new FakeCert { Id = "b", Desc = "Certadel nas.test" });

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Installer(dsm).InstallAsync(Bundle("nas.test"), Context(Options()), CancellationToken.None).AsTask());

        Assert.Contains("2 DSM certificates", ex.Message);
        Assert.Empty(dsm.Imports);
        Assert.Equal("SYNO.API.Auth.logout", dsm.Calls[^1]);
    }

    [Fact]
    public async Task UnknownService_FailsBeforeChangingAnything_NamingWhatIsAvailable()
    {
        var dsm = DsmWithSystemCert();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Installer(dsm).InstallAsync(Bundle("nas.test"),
                Context(Options(services: "DSM Desktop Service, typo.example.com")), CancellationToken.None).AsTask());

        Assert.Contains("typo.example.com", ex.Message);
        Assert.Contains("nothing was changed", ex.Message);
        Assert.Contains("nas.example.com", ex.Message); // lists what exists
        Assert.Empty(dsm.Imports);
        Assert.Equal(0, dsm.ServiceSetCalls);
    }

    [Fact]
    public async Task Asterisk_MixedWithNames_IsRejected()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Installer(DsmWithSystemCert()).InstallAsync(Bundle("nas.test"),
                Context(Options(services: "*, DSM Desktop Service")), CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task SessionEndingAfterImport_IsRecovered_BySigningInAgain()
    {
        var dsm = DsmWithSystemCert();
        dsm.EndSessionAfterImport = true;

        var result = await Installer(dsm).InstallAsync(Bundle("nas.test"),
            Context(Options(services: "DSM Desktop Service")), CancellationToken.None);

        Assert.True(result.Applied);
        Assert.Equal(2, dsm.Logins);
        Assert.Single(dsm.Imports);
        Assert.Equal("DSM Desktop Service",
            (string)Assert.Single(dsm.Certs.Single(c => c.Id != "sys").Services)["display_name"]!);
    }

    [Fact]
    public async Task SessionEndingDuringImport_IsVerified_NotRepeated()
    {
        var dsm = DsmWithSystemCert();
        dsm.EndSessionDuringImport = true;

        var result = await Installer(dsm).InstallAsync(Bundle("nas.test"), Context(Options()), CancellationToken.None);

        Assert.True(result.Applied);
        Assert.Single(dsm.Imports);
        Assert.Single(dsm.Certs, c => c.Id != "sys");
    }

    [Fact]
    public async Task InterruptedReplacement_WithUnchangedExpiry_IsReportedAsUnconfirmed()
    {
        var dsm = DsmWithSystemCert();
        var installer = Installer(dsm);
        var bundle = Bundle("nas.test");
        await installer.InstallAsync(bundle, Context(Options()), CancellationToken.None);
        dsm.DropConnectionAfterImport = true;

        var result = await installer.InstallAsync(bundle, Context(Options()), CancellationToken.None);

        Assert.True(result.Applied);
        Assert.Contains("could not be confirmed", result.Detail);
    }

    [Fact]
    public async Task ConnectionDropDuringImport_IsRecovered_ByFindingTheImportedCert()
    {
        var dsm = DsmWithSystemCert();
        dsm.DropConnectionAfterImport = true;

        var result = await Installer(dsm).InstallAsync(Bundle("nas.test"),
            Context(Options(services: "DSM Desktop Service")), CancellationToken.None);

        Assert.True(result.Applied);
        Assert.Single(dsm.Imports);
        Assert.Equal("DSM Desktop Service",
            (string)Assert.Single(dsm.Certs.Single(c => c.Id != "sys").Services)["display_name"]!);
    }

    [Fact]
    public async Task WrongPassword_FailsWithoutImporting()
    {
        var dsm = DsmWithSystemCert();
        var installer = new DsmInstaller(
            new FixedSecret("nope"), NullLogger<DsmInstaller>.Instance,
            endpoint => new DsmApiClient(endpoint, new HttpClient(dsm), ownsHttp: true), TimeSpan.Zero);

        await Assert.ThrowsAsync<DsmApiException>(() =>
            installer.InstallAsync(Bundle("nas.test"), Context(Options()), CancellationToken.None).AsTask());

        Assert.Empty(dsm.Imports);
    }

    [Theory]
    [InlineData("", "dsm-admin")]
    [InlineData(Account, "")]
    public async Task MissingAccountOrSecret_IsRejected(string account, string secret)
    {
        var opts = Options() with { Account = account, PasswordSecretName = secret };

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Installer(DsmWithSystemCert()).InstallAsync(Bundle("nas.test"), Context(opts), CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task Capability_IsDsmOnly()
    {
        var capability = await Installer(new FakeDsm()).CheckAsync(CancellationToken.None);

        Assert.Equal(DsmPlatform.IsDsm, capability.Available);
    }

    [Theory]
    [InlineData("", new string[0])]
    [InlineData("DSM Desktop Service", new[] { "DSM Desktop Service" })]
    [InlineData(" a.example.com ,b.example.com\nc.example.com;; ", new[] { "a.example.com", "b.example.com", "c.example.com" })]
    public void ServiceList_IsSplitOnCommasSemicolonsAndNewlines(string raw, string[] expected) =>
        Assert.Equal(expected, DsmInstaller.ParseServiceNames(raw));

    private sealed class FixedSecret(string value) : ISecretResolver
    {
        public Task<string> ResolveAsync(string name, CancellationToken ct) => Task.FromResult(value);
    }
}
