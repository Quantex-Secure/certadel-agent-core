using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Nodes;

using AcmeManager.Core.Storage;
using AcmeManager.Service.Migration.AcmeSh;
using AcmeManager.Service.Migration.WinAcme;

using Microsoft.EntityFrameworkCore;
using Microsoft.Web.Administration;

namespace AcmeManager.Service.Handoff;

/// <summary>One old-tool renewal that acme-manager has taken over and can be told to
/// stop renewing. <see cref="DisplayCommand"/> is shown; <see cref="File"/>+<see cref="Args"/>
/// are what actually runs.</summary>
internal sealed record HandoffCandidate(
    string Tool,
    string Target,
    string CoveredBy,
    string DisplayCommand,
    string File,
    IReadOnlyList<string> Args);

internal sealed record HandoffPreview(string? Error, string Tool, IReadOnlyList<HandoffCandidate> Candidates, string? WacsPath = null);

internal sealed record HandoffResult(string? Error, int Done, int Failed, IReadOnlyList<(string Target, string Status)> Items);

/// <summary>
/// The migration's last step: tell the old tool (acme.sh on Linux, win-acme on Windows)
/// to stop renewing a cert that acme-manager has taken over, so the two don't both renew
/// it. A candidate is only offered when acme-manager has <em>actually issued</em> a cert
/// covering the old tool's primary domain — proof the handover is real. The deregister
/// commands (<c>acme.sh --remove</c>, <c>wacs --cancel</c>) leave the cert files, bindings,
/// and config untouched; they only stop future renewals.
/// </summary>
internal sealed class HandoffService(AcmeManagerDbContext db, ILogger<HandoffService> logger)
{
    private const string DefaultWacsPath = @"C:\Program Files\win-acme\wacs.exe";

    public async Task<HandoffPreview> PreviewAsync(string? wacsPath, CancellationToken ct)
    {
        var managed = await ManagedDomainsAsync(ct);
        if (OperatingSystem.IsWindows())
        {
            var wacs = ResolveWacs(wacsPath);
            return new HandoffPreview(null, "win-acme", WinAcmeCandidates(managed, wacs), wacs);
        }
        return new HandoffPreview(null, "acme.sh", AcmeShCandidates(managed));
    }

    /// <summary>win-acme is "extract anywhere", so there's no fixed install path. Honour
    /// an explicit path; otherwise probe the common locations.</summary>
    internal static string ResolveWacs(string? given)
    {
        if (!string.IsNullOrWhiteSpace(given))
        {
            return given.Trim();
        }
        foreach (var candidate in WacsCandidates)
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        return DefaultWacsPath;
    }

    private static readonly string[] WacsCandidates =
    [
        @"C:\Program Files\win-acme\wacs.exe",
        @"C:\Program Files (x86)\win-acme\wacs.exe",
        @"C:\win-acme\wacs.exe",
        @"C:\tools\win-acme\wacs.exe",
        @"C:\ProgramData\win-acme\wacs.exe",
    ];

    public async Task<HandoffResult> ApplyAsync(string? wacsPath, IReadOnlyCollection<string>? onlyTargets, CancellationToken ct)
    {
        var preview = await PreviewAsync(wacsPath, ct);
        if (preview.Error is not null)
        {
            return new HandoffResult(preview.Error, 0, 0, []);
        }

        // Fail fast with one clear message rather than N identical "file not found" rows.
        if (OperatingSystem.IsWindows() && preview.Candidates.Count > 0 && preview.WacsPath is { } w && !File.Exists(w))
        {
            return new HandoffResult(
                $"win-acme executable not found at '{w}'. Set the correct wacs.exe path and retry.", 0, 0, []);
        }

        var candidates = preview.Candidates.AsEnumerable();
        if (onlyTargets is { Count: > 0 })
        {
            var pick = new HashSet<string>(onlyTargets, StringComparer.OrdinalIgnoreCase);
            candidates = candidates.Where(c => pick.Contains(c.Target));
        }

        var items = new List<(string, string)>();
        var done = 0;
        var failed = 0;
        foreach (var candidate in candidates)
        {
            try
            {
                await RunAsync(candidate.File, candidate.Args, ct);
                items.Add((candidate.Target, "deregistered"));
                done++;
                logger.LogInformation("Handoff: deregistered {Target} from {Tool}", candidate.Target, candidate.Tool);
            }
            catch (Exception ex)
            {
                items.Add((candidate.Target, $"failed — {ex.Message}"));
                failed++;
                logger.LogWarning(ex, "Handoff: failed to deregister {Target} from {Tool}", candidate.Target, candidate.Tool);
            }
        }
        return new HandoffResult(null, done, failed, items);
    }

    /// <summary>Domains acme-manager has actually issued a cert for (CN + SANs of every
    /// issued cert) → the renewal that owns it. The safe "we've taken this over" signal.</summary>
    private async Task<IReadOnlyDictionary<string, string>> ManagedDomainsAsync(CancellationToken ct)
    {
        var renewalNames = await db.Renewals.AsNoTracking().ToDictionaryAsync(r => r.Id, r => r.Name, ct);
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var cert in await db.Certificates.AsNoTracking().ToListAsync(ct))
        {
            var name = renewalNames.GetValueOrDefault(cert.RenewalId, "(renewal removed)");
            foreach (var domain in DomainsOf(cert.Subject, cert.SansJson))
            {
                map[domain] = name;
            }
        }
        return map;
    }

    /// <summary>CN (from "CN=...") + the SAN list of an issued cert.</summary>
    internal static IEnumerable<string> DomainsOf(string subject, string sansJson)
    {
        foreach (var part in subject.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                yield return part[3..].Trim();
            }
        }
        JsonNode? sans = null;
        if (!string.IsNullOrWhiteSpace(sansJson))
        {
            // Narrowed to JsonException so only malformed JSON is ignored, not
            // unexpected failures.
            try { sans = JsonNode.Parse(sansJson); }
            catch (JsonException) { /* malformed → no SANs */ }
        }
        if (sans is JsonArray array)
        {
            foreach (var n in array)
            {
                if (n is not null)
                {
                    yield return n.ToString();
                }
            }
        }
    }

    private static List<HandoffCandidate> AcmeShCandidates(IReadOnlyDictionary<string, string> managed)
    {
        var list = new List<HandoffCandidate>();
        var homes = AcmeShReader.ResolveHomes(null);
        foreach (var conf in AcmeShReader.ReadRenewals(homes))
        {
            if (!managed.TryGetValue(conf.Domain, out var coveredBy))
            {
                continue;
            }
            var home = Path.GetDirectoryName(Path.GetDirectoryName(conf.SourcePath)) ?? "";
            var script = Path.Combine(home, "acme.sh");
            var ecc = IsEcc(conf.SourcePath);
            var args = new List<string> { script, "--home", home, "--remove", "-d", conf.Domain };
            if (ecc)
            {
                args.Add("--ecc");
            }
            var display = $"acme.sh --home {home} --remove -d {conf.Domain}{(ecc ? " --ecc" : "")}";
            list.Add(new HandoffCandidate("acme.sh", conf.Domain, coveredBy, display, "/bin/sh", args));
        }
        return list;
    }

    /// <summary>acme.sh stores ECC certs in a <c>&lt;domain&gt;_ecc</c> directory.</summary>
    internal static bool IsEcc(string confPath)
    {
        var dir = Path.GetFileName(Path.GetDirectoryName(confPath) ?? "");
        return dir.EndsWith("_ecc", StringComparison.OrdinalIgnoreCase);
    }

    [SupportedOSPlatform("windows")]
    private List<HandoffCandidate> WinAcmeCandidates(IReadOnlyDictionary<string, string> managed, string wacs)
    {
        var list = new List<HandoffCandidate>();
        var baseDir = WinAcmeStore.ResolveBaseDir(null);
        if (baseDir is null)
        {
            return list;
        }

        // IIS "any host" renewals carry their domains in the site bindings, not the
        // renewal JSON — resolve site id → hosts live, the same way the importer does.
        var siteHosts = BuildIisSiteHosts();
        foreach (var ca in WinAcmeStore.Read(baseDir).CaFolders)
        {
            foreach (var renewal in ca.Renewals)
            {
                var id = renewal.Root["Id"]?.ToString();
                if (id is null)
                {
                    continue;
                }
                var coveredBy = RenewalDomains(renewal.Root, sid => siteHosts.GetValueOrDefault(sid, []))
                    .Select(managed.GetValueOrDefault)
                    .FirstOrDefault(name => name is not null);
                if (coveredBy is null)
                {
                    continue;
                }
                var friendly = renewal.Root["LastFriendlyName"]?.ToString() ?? id;
                var (display, cancelArgs) = WinAcmeCancel(id);
                list.Add(new HandoffCandidate("win-acme", friendly, coveredBy, display, wacs, cancelArgs));
            }
        }
        return list;
    }

    /// <summary>All hostnames a win-acme renewal covers: explicit CommonName + SANs, plus
    /// the binding hosts of any IIS site it targets (resolved via <paramref name="siteHostsFor"/>).</summary>
    internal static IEnumerable<string> RenewalDomains(JsonObject root, Func<string, IReadOnlyList<string>> siteHostsFor)
    {
        if (root["TargetPluginOptions"] is not JsonObject target)
        {
            yield break;
        }
        if (target["CommonName"]?.ToString() is { Length: > 0 } cn)
        {
            yield return cn;
        }
        if (target["AlternativeNames"] is JsonArray alts)
        {
            foreach (var alt in alts)
            {
                if (alt?.ToString() is { Length: > 0 } name)
                {
                    yield return name;
                }
            }
        }
        foreach (var siteId in SiteIds(target))
        {
            foreach (var host in siteHostsFor(siteId))
            {
                yield return host;
            }
        }
    }

    /// <summary>The <c>wacs --cancel --id</c> command for a renewal. win-acme renewal ids
    /// are URL-safe base64 and can start with '-'; its parser then reads the value as an
    /// option unless it's double-escaped (one layer of quotes the parser strips). See the
    /// win-acme CLI reference.</summary>
    internal static (string Display, string[] Args) WinAcmeCancel(string id)
    {
        if (id.StartsWith('-'))
        {
            return ($"wacs.exe --cancel --id \"\\\"{id}\\\"\"", ["--cancel", "--id", $"\"{id}\""]);
        }
        return ($"wacs.exe --cancel --id {id}", ["--cancel", "--id", id]);
    }

    private static IEnumerable<string> SiteIds(JsonObject target)
    {
        if (target["IncludeSiteIds"] is JsonArray arr)
        {
            foreach (var s in arr)
            {
                if (s?.ToString() is { Length: > 0 } v)
                {
                    yield return v;
                }
            }
        }
        if (target["SiteId"]?.ToString() is { Length: > 0 } sid)
        {
            yield return sid;
        }
    }

    [SupportedOSPlatform("windows")]
    private Dictionary<string, IReadOnlyList<string>> BuildIisSiteHosts()
    {
        var map = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var server = new ServerManager();
            foreach (var site in server.Sites)
            {
                map[site.Id.ToString()] = site.Bindings
                    .Select(b => b.Host)
                    .Where(h => !string.IsNullOrEmpty(h))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }
        }
        catch (Exception ex)
        {
            // IIS not present / no access — no site hosts to add.
            logger.LogDebug(ex, "Handoff: could not enumerate IIS site hosts.");
        }
        return map;
    }

    private async Task RunAsync(string file, IReadOnlyList<string> args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(file)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"could not start {file}");
        // Drain BOTH pipes concurrently: a chatty wacs.exe/acme.sh fills the 4 KB
        // stdout buffer and would block forever if only stderr were read, turning a
        // successful deregistration into a timeout (and a double-renewing old tool).
        var stdout = process.StandardOutput.ReadToEndAsync(ct);
        var stderr = process.StandardError.ReadToEndAsync(ct);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromMinutes(2));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
            throw new TimeoutException("deregister command timed out");
        }

        var output = (await stdout).Trim();
        if (process.ExitCode != 0)
        {
            var err = (await stderr).Trim();
            var detail = err.Length > 0 ? err : output;
            throw new InvalidOperationException($"exit {process.ExitCode}{(detail.Length > 0 ? $": {detail}" : "")}");
        }
        if (output.Length > 0)
        {
            logger.LogDebug("Handoff: {File} said: {Output}", file, output);
        }
    }
}