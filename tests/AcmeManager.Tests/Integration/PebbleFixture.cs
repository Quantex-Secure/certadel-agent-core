using System.Diagnostics;
using System.Net.Http;
using System.Net.Security;
using System.Text.Json;

namespace AcmeManager.Tests.Integration;

/// <summary>
/// Starts <c>pebble</c> + <c>pebble-challtestsrv</c> as subprocesses for the
/// life of the test collection, then tears them down. If the binaries aren't
/// present at <see cref="BinariesDir"/>, tests opt into the fixture should
/// call <see cref="EnsureAvailableOrSkip"/> — they'll be skipped cleanly
/// with a hint to run <c>scripts/download-pebble.ps1</c>.
///
/// Process layout:
///   pebble  → ACME directory: https://localhost:14000/dir
///             management:     https://localhost:15000
///   pebble-challtestsrv → HTTP challenges on :5002, mgmt API on :8055
/// </summary>
public sealed class PebbleFixture : IAsyncLifetime
{
    public const int PebbleAcmePort = 14000;
    public const int PebbleManagementPort = 15000;
    public const int ChallTestSrvHttpPort = 5002;
    public const int ChallTestSrvMgmtPort = 8055;
    public const int ChallTestSrvDnsPort = 8053;

    public Uri AcmeDirectoryUrl { get; } = new($"https://localhost:{PebbleAcmePort}/dir");
    public Uri ChallTestSrvMgmtUrl { get; } = new($"http://localhost:{ChallTestSrvMgmtPort}");

    public string BinariesDir { get; }
    public string PebbleExe { get; }
    public string ChallTestSrvExe { get; }
    public string CertPem { get; }
    public string KeyPem { get; }

    public bool Available => File.Exists(PebbleExe) && File.Exists(ChallTestSrvExe) && File.Exists(CertPem) && File.Exists(KeyPem);

    private Process? _pebble;
    private Process? _challTestSrv;
    private string? _configPath;

    public PebbleFixture()
    {
        var repoRoot = FindRepoRoot();
        BinariesDir = Path.Combine(repoRoot, "tests", ".pebble");
        var exe = OperatingSystem.IsWindows() ? ".exe" : "";
        PebbleExe = Path.Combine(BinariesDir, "pebble" + exe);
        ChallTestSrvExe = Path.Combine(BinariesDir, "pebble-challtestsrv" + exe);
        CertPem = Path.Combine(BinariesDir, "cert.pem");
        KeyPem = Path.Combine(BinariesDir, "key.pem");
    }

    public void EnsureAvailableOrSkip()
    {
        Skip.IfNot(Available,
            $"Pebble binaries missing at {BinariesDir}. Run scripts/download-pebble.ps1 once to fetch them.");
    }

    public async Task InitializeAsync()
    {
        if (!Available)
        {
            return;
        }

        _configPath = WriteConfig();

        // -dnsserver points Pebble's VA at challtestsrv's mock DNS below so the
        // ".test" challenge identifiers resolve (the system resolver never would).
        _pebble = StartProcess(PebbleExe,
            args: $"-config \"{_configPath}\" -strict -dnsserver 127.0.0.1:{ChallTestSrvDnsPort}",
            env: new Dictionary<string, string?>
            {
                ["PEBBLE_VA_NOSLEEP"] = "1",
                ["PEBBLE_WFE_NONCEREJECT"] = "0",
            });

        // challtestsrv provides a mock DNS resolver (returns 127.0.0.1 for any A query)
        // that Pebble's VA (via -dnsserver above) uses to resolve test identifiers.
        // Its DNS bind flag is -dnsserver (renamed from -dns01 in newer releases).
        _challTestSrv = StartProcess(ChallTestSrvExe,
            args: $"-management :{ChallTestSrvMgmtPort} -http01 :{ChallTestSrvHttpPort} -dnsserver :{ChallTestSrvDnsPort} -tlsalpn01 \"\" -doh \"\" -https01 \"\"",
            env: null);

        await WaitForAcmeDirectoryAsync(TimeSpan.FromSeconds(15));
    }

    public Task DisposeAsync()
    {
        TryKill(_pebble);
        TryKill(_challTestSrv);
        if (_configPath is not null && File.Exists(_configPath))
        {
            try { File.Delete(_configPath); } catch { /* best-effort */ }
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// Builds an <see cref="HttpClient"/> that trusts Pebble's self-signed
    /// cert. Pebble is local to this test process, so accepting any cert is
    /// scoped purely to the test fixture's HTTP traffic.
    /// </summary>
    public HttpClient CreatePebbleTrustingHttpClient()
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
        };
        return new HttpClient(handler);
    }

    private string WriteConfig()
    {
        var config = new
        {
            pebble = new
            {
                listenAddress = $"0.0.0.0:{PebbleAcmePort}",
                managementListenAddress = $"0.0.0.0:{PebbleManagementPort}",
                certificate = CertPem.Replace("\\", "/"),
                privateKey = KeyPem.Replace("\\", "/"),
                httpPort = ChallTestSrvHttpPort,
                tlsPort = 5001,
                ocspResponderURL = "",
                externalAccountBindingRequired = false,
                domainBlocklist = new[] { "example.org" },
                retryAfter = new { authz = 1, order = 1 },
            },
        };
        var path = Path.Combine(BinariesDir, "pebble-config.runtime.json");
        File.WriteAllText(path, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
        return path;
    }

    private static Process StartProcess(string exe, string args, IDictionary<string, string?>? env)
    {
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        if (env is not null)
        {
            foreach (var kv in env)
            {
                psi.Environment[kv.Key] = kv.Value;
            }
        }
        var p = Process.Start(psi) ?? throw new InvalidOperationException($"Failed to start {exe}");
        // Drain output so the pipes don't fill up and block the child.
        _ = Task.Run(() => DrainAsync(p.StandardOutput));
        _ = Task.Run(() => DrainAsync(p.StandardError));
        return p;
    }

    private static async Task DrainAsync(StreamReader reader)
    {
        try
        {
            char[] buf = new char[1024];
            while (await reader.ReadAsync(buf, 0, buf.Length) > 0)
            {
                // intentionally discarded; Pebble logs are noisy and not useful to tests
            }
        }
        catch { /* process exited */ }
    }

    private async Task WaitForAcmeDirectoryAsync(TimeSpan timeout)
    {
        using var http = CreatePebbleTrustingHttpClient();
        // Pebble's strict mode enforces RFC 8555's "requests MUST include a
        // User-Agent" rule and 400s anything without one — so this health probe
        // must send a User-Agent or it never sees the directory come up.
        http.DefaultRequestHeaders.UserAgent.ParseAdd("acme-manager-pebble-fixture/1.0");
        var deadline = DateTime.UtcNow + timeout;
        Exception? last = null;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var resp = await http.GetAsync(AcmeDirectoryUrl);
                if (resp.IsSuccessStatusCode) return;
            }
            catch (Exception ex)
            {
                last = ex;
            }
            await Task.Delay(200);
        }
        throw new TimeoutException($"Pebble ACME directory at {AcmeDirectoryUrl} did not become reachable within {timeout}", last);
    }

    private static void TryKill(Process? p)
    {
        if (p is null) return;
        try
        {
            if (!p.HasExited) p.Kill(entireProcessTree: true);
            p.WaitForExit(5_000);
        }
        catch { /* ignore */ }
        p.Dispose();
    }

    // The agent source builds from CertadelAgent.slnx; the full product repo from AcmeManager.slnx.
    private static readonly string[] SolutionFiles = ["CertadelAgent.slnx", "AcmeManager.slnx"];

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !SolutionFiles.Any(f => File.Exists(Path.Combine(dir.FullName, f))))
        {
            dir = dir.Parent;
        }
        if (dir is null)
        {
            throw new InvalidOperationException($"Could not locate repo root ({string.Join(" or ", SolutionFiles)}).");
        }
        return dir.FullName;
    }
}

[CollectionDefinition(Name)]
public sealed class PebbleCollection : ICollectionFixture<PebbleFixture>
{
    public const string Name = "Pebble";
}