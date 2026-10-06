using System.Diagnostics;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Installation;
using AcmeManager.Plugins.Contracts.Storage;

using Microsoft.Extensions.Logging;
using Microsoft.Web.Administration;

namespace AcmeManager.Plugins.Iis;

public sealed record IisInstallerOptions : PluginOptions
{
    /// <summary>
    /// IIS site to bind within. Leave blank to scan every site on the host — handy to
    /// pre-place a cert before its site exists (it just sits in the store and binds on
    /// a later run), or to cover separate sites named for the cert's SANs. When set,
    /// the cert binds to every binding on that site whose host is one of its subject/SAN
    /// names, creating one from the common name if none exist yet.
    /// </summary>
    [IisSiteReference]
    public string SiteName { get; init; } = "";

    /// <summary>
    /// Optional explicit host to also ensure a binding for, even if it doesn't exist
    /// yet (created on <see cref="SiteName"/>). Normally unnecessary: the cert binds
    /// to every existing binding whose host is one of its subject/SAN names. Empty +
    /// Require SNI falls back to the certificate's common name only when nothing matched.
    /// </summary>
    public string Host { get; init; } = "";

    /// <summary>IP address; "*" for all interfaces.</summary>
    public string Ip { get; init; } = "*";

    public int Port { get; init; } = 443;

    /// <summary>
    /// Store reference key that holds the cert's thumbprint — must match a
    /// store plugin id in the renewal's Stores list. Defaults to the
    /// <c>store.winstore</c> plugin id.
    /// </summary>
    public string CertStoreReferenceKey { get; init; } = "store.winstore";

    /// <summary>Cert store name where the cert lives (must match the store plugin's
    /// config). UIs render this as a picker of the host's stores.</summary>
    [CertStoreReference]
    public string CertStoreName { get; init; } = "MY";

    /// <summary>
    /// Sets the SNI flag on the binding. Required if multiple HTTPS sites
    /// share the same IP:port with distinct host headers (the modern norm).
    /// </summary>
    public bool RequireSni { get; init; } = true;

    /// <summary>
    /// Endpoints to check after binding, comma-separated: <c>host</c>, <c>host:port</c>,
    /// or <c>name@host:port</c> (name = SNI). Empty = every binding this step touched,
    /// reached on loopback with the binding's host as SNI.
    /// </summary>
    public string VerifyEndpoints { get; init; } = "";

    /// <summary>
    /// Skips the post-install check for this step. The renewal is then recorded
    /// as unverified — use only where TLS is terminated elsewhere.
    /// </summary>
    public bool SkipVerification { get; init; }
}

/// <summary>One IIS binding to point at the issued cert.</summary>
internal sealed record BindingTarget(string Site, string BindingInfo, string Host);

/// <summary>What a binding pointed at before this run touched it, for rollback.</summary>
internal sealed record PreviousBinding(BindingTarget Target, byte[]? CertificateHash, string? StoreName, long SslFlags, bool Existed);

/// <summary>
/// Installer that wires the issued cert into IIS HTTPS bindings. The cert is bound
/// to <em>every</em> existing binding whose host header is one of the certificate's
/// subject/SAN names — so one SAN cert covers all the bindings it's valid for, and a
/// site running different certs on different bindings keeps each (a cert only claims
/// the bindings it actually covers). Scope is one site (<see cref="IisInstallerOptions.SiteName"/>)
/// or, when that's blank, every site on the host. Reads the thumbprint from
/// <see cref="InstallContext.StoreReferences"/>; repairs invalid SNI-without-host
/// bindings; retries once after clearing a conflicting HTTP.sys SSL registration on
/// E_INVALIDARG.
/// </summary>
public sealed class IisInstaller(ILogger<IisInstaller> logger) : IInstaller, ICapability
{
    public PluginMetadata Metadata { get; } = new(
        Id: "installer.iis",
        Name: "IIS binding",
        Description: "Binds the issued cert to every IIS binding whose host is one of its subject/SAN names (SNI by default).",
        Category: PluginCategory.Installation,
        Version: new Version(1, 2, 0));

    public ValueTask<CapabilityResult> CheckAsync(CancellationToken ct) =>
        ValueTask.FromResult(OperatingSystem.IsWindows()
            ? CapabilityResult.Yes
            : CapabilityResult.No("IIS installer requires Windows"));

    public ValueTask<InstallResult> InstallAsync(CertificateBundle bundle, InstallContext ctx, CancellationToken ct)
    {
        var opts = (IisInstallerOptions)ctx.Options;

        // Validate the operator's endpoint list before touching any binding, so a
        // typo can't fail the run after the certificate is already bound.
        var explicitEndpoints = VerificationOptions.Parse(opts.VerifyEndpoints, opts.Port, bundle.CommonName);

        if (!ctx.StoreReferences.TryGetValue(opts.CertStoreReferenceKey, out var thumbprint)
            || string.IsNullOrWhiteSpace(thumbprint))
        {
            throw new InvalidOperationException(
                $"IisInstaller: required store reference '{opts.CertStoreReferenceKey}' is missing. " +
                "Ensure that store plugin runs in the renewal's Stores list before this installer.");
        }

        var certNames = CertNames(bundle);
        var existing = EnumerateHttpsBindings(opts.SiteName);
        var targets = SelectTargets(certNames, existing, opts.Host, opts.Ip, opts.Port, opts.SiteName, opts.RequireSni, bundle.CommonName);

        if (targets.Count == 0)
        {
            // Nothing to bind (the site/binding doesn't exist, was renamed, or its
            // host doesn't match a name on the cert). The cert is issued and stored,
            // and will bind on a later run once a matching binding exists — but IIS
            // is still serving whatever it served before, so this is reported as a
            // warning, never as "installed".
            var scope = string.IsNullOrWhiteSpace(opts.SiteName) ? "any site" : $"site '{opts.SiteName}'";
            logger.LogWarning(
                "IIS installer: certificate names [{Names}] match no HTTPS binding on {Scope}; NOTHING BOUND — IIS keeps serving its current certificate.",
                string.Join(", ", certNames), scope);
            return ValueTask.FromResult(InstallResult.NothingToApply(
                $"no HTTPS binding on {scope} matches [{string.Join(", ", certNames)}]"));
        }

        var thumbprintBytes = Convert.FromHexString(thumbprint);

        // Repair invalid SNI-without-host bindings once per affected site before we touch bindings.
        foreach (var site in targets.Select(t => t.Site).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            RemoveCorruptSniBindings(site);
        }

        var previous = new List<PreviousBinding>();
        foreach (var target in targets)
        {
            previous.Add(BindWithRetry(target, thumbprintBytes, opts));
        }

        var bound = string.Join(", ", targets.Select(t => $"{t.Site} @ {t.BindingInfo}"));
        logger.LogInformation(
            "IIS installer: bound cert {Thumbprint} to {Count} binding(s): {List}",
            thumbprint, targets.Count, bound);

        return ValueTask.FromResult(InstallResult.Ok($"{targets.Count} binding(s): {bound}") with
        {
            Endpoints = opts.SkipVerification ? [] : explicitEndpoints.Count > 0 ? explicitEndpoints : DefaultEndpoints(targets, bundle.CommonName),
            VerificationSkippedReason = opts.SkipVerification ? VerificationOptions.SkippedByOperator : null,
            Rollback = _ =>
            {
                foreach (var p in Enumerable.Reverse(previous))
                {
                    RestoreBinding(p, opts);
                }
                logger.LogWarning("IIS installer: restored the previous certificate on {Count} binding(s)", previous.Count);
                return ValueTask.CompletedTask;
            },
        });
    }

    /// <summary>The certificate's name set (common name + SANs), case-insensitive.</summary>
    internal static IReadOnlySet<string> CertNames(CertificateBundle bundle)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(bundle.CommonName))
        {
            names.Add(bundle.CommonName.Trim());
        }
        foreach (var san in bundle.SubjectAlternativeNames)
        {
            if (!string.IsNullOrWhiteSpace(san))
            {
                names.Add(san.Trim());
            }
        }
        return names;
    }

    /// <summary>
    /// Pure binding-selection: every existing binding whose host is one of the cert's
    /// names, plus an explicit Host to ensure (when set), plus — only if nothing else
    /// matched — a common-name fallback so a brand-new site still gets a binding.
    /// </summary>
    internal static IReadOnlyList<BindingTarget> SelectTargets(
        IReadOnlySet<string> certNames,
        IReadOnlyList<BindingTarget> existingBindings,
        string? explicitHost,
        string ip,
        int port,
        string? siteName,
        bool requireSni,
        string? commonName)
    {
        var result = new List<BindingTarget>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var binding in existingBindings)
        {
            if (!string.IsNullOrEmpty(binding.Host)
                && certNames.Contains(binding.Host)
                && seen.Add($"{binding.Site}|{binding.BindingInfo}"))
            {
                result.Add(binding);
            }
        }

        if (!string.IsNullOrWhiteSpace(explicitHost) && !string.IsNullOrWhiteSpace(siteName))
        {
            var target = new BindingTarget(siteName, $"{ip}:{port}:{explicitHost.Trim()}", explicitHost.Trim());
            if (seen.Add($"{target.Site}|{target.BindingInfo}"))
            {
                result.Add(target);
            }
        }

        if (result.Count == 0 && requireSni && !string.IsNullOrWhiteSpace(siteName) && !string.IsNullOrWhiteSpace(commonName))
        {
            result.Add(new BindingTarget(siteName, $"{ip}:{port}:{commonName.Trim()}", commonName.Trim()));
        }

        return result;
    }

    /// <summary>
    /// Where to look for each touched binding: loopback (or the binding's own
    /// address when it isn't a wildcard), the binding's port, and its host as SNI
    /// — falling back to the certificate's common name for host-less bindings.
    /// </summary>
    internal static IReadOnlyList<VerifyEndpoint> DefaultEndpoints(IReadOnlyList<BindingTarget> targets, string commonName)
    {
        var endpoints = new List<VerifyEndpoint>();
        foreach (var target in targets)
        {
            var (ip, port) = ParseBindingAddress(target.BindingInfo);
            var serverName = string.IsNullOrWhiteSpace(target.Host) ? commonName : target.Host;
            var endpoint = new VerifyEndpoint(ip, port, serverName);
            if (!endpoints.Contains(endpoint))
            {
                endpoints.Add(endpoint);
            }
        }
        return endpoints;
    }

    /// <summary>
    /// The address to probe for an IIS <c>BindingInformation</c> ("ip:port:host",
    /// where ip may be <c>*</c>, an IPv4 address, or a bracketed IPv6 literal).
    /// Wildcards and unparseable addresses become loopback of the matching family.
    /// </summary>
    internal static (string Host, int Port) ParseBindingAddress(string bindingInformation)
    {
        // Host is after the last colon, port between the last two; everything
        // before that is the address (which itself may contain colons for IPv6).
        var lastColon = bindingInformation.LastIndexOf(':');
        var portColon = lastColon > 0 ? bindingInformation.LastIndexOf(':', lastColon - 1) : -1;
        var address = portColon > 0 ? bindingInformation[..portColon] : "";
        var portText = portColon >= 0 ? bindingInformation[(portColon + 1)..lastColon] : "";
        var port = int.TryParse(portText, out var parsedPort) && parsedPort is > 0 and <= 65535 ? parsedPort : 443;

        var trimmed = address.Trim().TrimStart('[').TrimEnd(']');
        if (System.Net.IPAddress.TryParse(trimmed, out var parsed))
        {
            if (parsed.Equals(System.Net.IPAddress.Any))
            {
                return ("127.0.0.1", port);
            }
            if (parsed.Equals(System.Net.IPAddress.IPv6Any))
            {
                return ("::1", port);
            }
            return (parsed.ToString(), port);
        }
        return ("127.0.0.1", port);
    }

    /// <summary>The host header from an IIS <c>BindingInformation</c> ("ip:port:host").</summary>
    internal static string BindingHost(string bindingInformation)
    {
        var parts = bindingInformation.Split(':', 3);
        return parts.Length == 3 ? parts[2] : "";
    }

    private static List<BindingTarget> EnumerateHttpsBindings(string? siteName)
    {
        var result = new List<BindingTarget>();
        using var serverManager = new ServerManager();
        var sites = string.IsNullOrWhiteSpace(siteName)
            ? serverManager.Sites.AsEnumerable()
            : serverManager.Sites.Where(s => string.Equals(s.Name, siteName, StringComparison.OrdinalIgnoreCase));
        foreach (var site in sites)
        {
            foreach (var binding in site.Bindings.Where(b => b.Protocol == "https"))
            {
                result.Add(new BindingTarget(site.Name, binding.BindingInformation, BindingHost(binding.BindingInformation)));
            }
        }
        return result;
    }

    private PreviousBinding BindWithRetry(BindingTarget target, byte[] thumbprintBytes, IisInstallerOptions opts)
    {
        try
        {
            return BindCertificate(target, thumbprintBytes, opts);
        }
        catch (ArgumentException firstEx)
        {
            // E_INVALIDARG from CommitChanges — usually a stale HTTP.sys SSL
            // registration whose key shape no longer matches the binding config.
            logger.LogWarning(firstEx,
                "IIS binding commit for {Site} {Binding} failed with E_INVALIDARG; clearing the HTTP.sys SSL registration and retrying once",
                target.Site, target.BindingInfo);
            TryDeleteHttpSysSslRecord(target.Host.Length > 0 && opts.RequireSni
                ? $"hostnameport={target.Host}:{opts.Port}"
                : $"ipport={(opts.Ip == "*" ? "0.0.0.0" : opts.Ip)}:{opts.Port}");
            try
            {
                return BindCertificate(target, thumbprintBytes, opts);
            }
            catch (ArgumentException retryEx)
            {
                throw new InvalidOperationException(
                    $"IIS rejected the binding update for {target.Site} {target.BindingInfo} twice (E_INVALIDARG). This is usually a " +
                    $"stale HTTP.sys SSL registration from a pre-SNI binding. Run 'netsh http show sslcert' on this server and delete " +
                    $"the conflicting record (e.g. 'netsh http delete sslcert ipport=0.0.0.0:{opts.Port}'), then renew again.",
                    retryEx);
            }
        }
    }

    private PreviousBinding BindCertificate(BindingTarget target, byte[] thumbprintBytes, IisInstallerOptions opts)
    {
        using var serverManager = new ServerManager();
        var site = serverManager.Sites.FirstOrDefault(s =>
                       string.Equals(s.Name, target.Site, StringComparison.OrdinalIgnoreCase))
                   ?? throw new InvalidOperationException($"IIS site '{target.Site}' not found");

        var existing = site.Bindings.FirstOrDefault(b =>
            b.Protocol == "https" && b.BindingInformation == target.BindingInfo);
        var previous = existing is null
            ? new PreviousBinding(target, null, null, 0, Existed: false)
            : new PreviousBinding(target, existing.CertificateHash, existing.CertificateStoreName,
                Convert.ToInt64(existing.GetAttributeValue("sslFlags") ?? 0L), Existed: true);
        if (existing is not null)
        {
            site.Bindings.Remove(existing);
        }

        var newBinding = site.Bindings.Add(target.BindingInfo, thumbprintBytes, opts.CertStoreName);
        newBinding.Protocol = "https";
        if (opts.RequireSni)
        {
            newBinding.SetAttributeValue("sslFlags", 1); // SslFlags.Sni
        }

        serverManager.CommitChanges();
        return previous;
    }

    /// <summary>Puts a binding back the way <see cref="BindCertificate"/> found it.</summary>
    private void RestoreBinding(PreviousBinding previous, IisInstallerOptions opts)
    {
        try
        {
            using var serverManager = new ServerManager();
            var site = serverManager.Sites.FirstOrDefault(s =>
                string.Equals(s.Name, previous.Target.Site, StringComparison.OrdinalIgnoreCase));
            if (site is null)
            {
                return;
            }
            var current = site.Bindings.FirstOrDefault(b =>
                b.Protocol == "https" && b.BindingInformation == previous.Target.BindingInfo);
            if (current is not null)
            {
                site.Bindings.Remove(current);
            }
            if (previous.Existed)
            {
                // Put the binding back exactly as found: same certificate (or none), same
                // store, same SSL flags (SNI / central store), not this run's settings.
                var restored = previous.CertificateHash is { Length: > 0 }
                    ? site.Bindings.Add(previous.Target.BindingInfo, previous.CertificateHash, previous.StoreName ?? opts.CertStoreName)
                    : site.Bindings.Add(previous.Target.BindingInfo, "https");
                restored.Protocol = "https";
                restored.SetAttributeValue("sslFlags", previous.SslFlags);
            }
            serverManager.CommitChanges();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"could not restore the previous certificate on {previous.Target.Site} {previous.Target.BindingInfo}: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Removes https bindings that have the SNI flag but no host name — an
    /// invalid combination (older agent versions could write one). Edits the raw
    /// config section in its own session: the typed Bindings API can't commit a
    /// removal of these without throwing the very E_INVALIDARG we're avoiding.
    /// </summary>
    private void RemoveCorruptSniBindings(string siteName)
    {
        try
        {
            using var serverManager = new ServerManager();
            var sites = serverManager.GetApplicationHostConfiguration()
                .GetSection("system.applicationHost/sites")
                .GetCollection();
            var site = sites.FirstOrDefault(s =>
                string.Equals((string)s["name"], siteName, StringComparison.OrdinalIgnoreCase));
            if (site is null)
            {
                return;
            }

            var bindings = site.GetCollection("bindings");
            var corrupt = bindings.Where(b =>
                string.Equals((string)b["protocol"], "https", StringComparison.OrdinalIgnoreCase)
                && ((string)b["bindingInformation"]).EndsWith(':')
                && Convert.ToInt64(b["sslFlags"] ?? 0L) != 0).ToList();
            if (corrupt.Count == 0)
            {
                return;
            }

            foreach (var binding in corrupt)
            {
                bindings.Remove(binding);
            }
            serverManager.CommitChanges();
            logger.LogWarning(
                "Removed {Count} invalid SNI-without-host HTTPS binding(s) from IIS site '{Site}'",
                corrupt.Count, siteName);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not check IIS site '{Site}' for corrupt SNI bindings; continuing", siteName);
        }
    }

    private void TryDeleteHttpSysSslRecord(string key)
    {
        try
        {
            var psi = new ProcessStartInfo("netsh", $"http delete sslcert {key}")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var process = Process.Start(psi);
            if (process is null)
            {
                return;
            }
            process.WaitForExit(10_000);
            logger.LogInformation("netsh http delete sslcert {Key} exited with {Code}", key, process.ExitCode);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "netsh http delete sslcert {Key} failed; continuing", key);
        }
    }
}