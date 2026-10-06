using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Installation;
using AcmeManager.Plugins.Contracts.Storage;

using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.Linux.Synology;

public sealed record DsmInstallerOptions : PluginOptions
{
    /// <summary>DSM administrator the agent signs in as, e.g. <c>EXAMPLE\name</c>. Required.</summary>
    [RequiredOption]
    public string Account { get; init; } = "";

    /// <summary>That account's password. Write-only: on save it is stored encrypted as
    /// an agent secret (<c>Synology DSM: &lt;account&gt;</c>) and never kept in the
    /// renewal. Leave blank when editing to keep the stored one.</summary>
    [InlineSecret(nameof(PasswordSecretName), NamePrefix = "Synology DSM", NameSuffixProperty = nameof(Account))]
    public string Password { get; init; } = "";

    /// <summary>The agent secret holding the password; set automatically from
    /// <see cref="Password"/> and hidden from forms.</summary>
    [SecretReference]
    public string PasswordSecretName { get; init; } = "";

    /// <summary>Description of the certificate in DSM (Control Panel → Security →
    /// Certificate), and how renewals find it to replace in place — so it must be
    /// unique per renewal (e.g. give a staging copy its own). Blank =
    /// <c>Certadel &lt;common name&gt;</c>.</summary>
    public string Description { get; init; } = "";

    /// <summary>DSM services to use this certificate, by the name DSM shows in the
    /// certificate settings: <c>System default</c> (also accepted as <c>DSM Desktop
    /// Service</c>, its API name), reverse-proxy hostnames, etc.
    /// Comma- or line-separated. <c>*</c> alone = every service, taking them from any
    /// other certificate. Blank = import only. Bindings are kept across renewals.</summary>
    public string Services { get; init; } = "";

    /// <summary>Make this DSM's default certificate (used by services added later).</summary>
    public bool AsDefault { get; init; }

    /// <summary>DSM Web API address. Blank = <c>http://127.0.0.1:5000</c> on this NAS.</summary>
    public string DsmUrl { get; init; } = "";
}

/// <summary>
/// Installs the certificate into Synology DSM through its Web API — the only route
/// for an unprivileged DSM 7 package. The first run imports a new DSM certificate
/// and binds the requested services; renewals replace that same certificate in
/// place (matched by description), which keeps every binding, including any made
/// by hand in DSM.
///
/// DSM restarts its web server after imports and re-binds, which can drop the
/// connection or end the session mid-call. Changes are therefore never retried
/// blindly: after a dropped connection or expired session the installer signs in
/// again if needed and verifies the outcome by reading DSM's certificate list.
/// Requested services are validated before anything in DSM is changed.
/// </summary>
public sealed class DsmInstaller : IInstaller, ICapability
{
    public const string DefaultEndpoint = "http://127.0.0.1:5000";
    private const string DefaultDescriptionPrefix = "Certadel ";
    private const string AllServices = "*";
    private const int VerifyAttempts = 30;
    private static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan ExpiryTolerance = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan LogoutTimeout = TimeSpan.FromSeconds(5);

    private readonly ISecretResolver _secrets;
    private readonly ILogger<DsmInstaller> _logger;
    private readonly Func<Uri, DsmApiClient> _clientFactory;
    private readonly TimeSpan _pollInterval;

    public DsmInstaller(ISecretResolver secrets, ILogger<DsmInstaller> logger)
        : this(secrets, logger, endpoint => new DsmApiClient(endpoint), DefaultPollInterval)
    {
    }

    internal DsmInstaller(
        ISecretResolver secrets,
        ILogger<DsmInstaller> logger,
        Func<Uri, DsmApiClient> clientFactory,
        TimeSpan pollInterval)
    {
        _secrets = secrets;
        _logger = logger;
        _clientFactory = clientFactory;
        _pollInterval = pollInterval;
    }

    public PluginMetadata Metadata { get; } = new(
        Id: "installer.synology-dsm",
        Name: "Synology DSM",
        Description: "Imports the certificate into DSM and binds it to DSM services and reverse-proxy hostnames.",
        Category: PluginCategory.Installation,
        Version: new Version(1, 0, 0));

    public ValueTask<CapabilityResult> CheckAsync(CancellationToken ct) =>
        ValueTask.FromResult(DsmPlatform.IsDsm
            ? CapabilityResult.Yes
            : CapabilityResult.No("Synology DSM installer runs only on a Synology NAS"));

    public async ValueTask<InstallResult> InstallAsync(CertificateBundle bundle, InstallContext ctx, CancellationToken ct)
    {
        var opts = (DsmInstallerOptions)ctx.Options;
        if (string.IsNullOrWhiteSpace(opts.Account))
        {
            throw new InvalidOperationException("Synology DSM installer: Account is required.");
        }
        if (string.IsNullOrWhiteSpace(opts.PasswordSecretName))
        {
            throw new InvalidOperationException("Synology DSM installer: enter the DSM account's password and save.");
        }
        var services = ParseServiceNames(opts.Services);
        if (services.Contains(AllServices) && services.Count > 1)
        {
            throw new InvalidOperationException("Synology DSM installer: use '*' on its own, or list services by name.");
        }

        var (keyPem, leafPem, intermediatesPem) = LinuxCertMaterial.SplitPem(bundle);
        var target = new Target(
            Description: string.IsNullOrWhiteSpace(opts.Description)
                ? DefaultDescriptionPrefix + bundle.CommonName
                : opts.Description.Trim(),
            Services: services,
            AsDefault: opts.AsDefault,
            NotAfter: bundle.NotAfter,
            Material: new DsmCertificateMaterial(keyPem, leafPem, intermediatesPem));

        var endpoint = new Uri(string.IsNullOrWhiteSpace(opts.DsmUrl) ? DefaultEndpoint : opts.DsmUrl.Trim());
        var password = await _secrets.ResolveAsync(opts.PasswordSecretName, ct);

        using var client = _clientFactory(endpoint);
        var dsm = new Connection(client, opts.Account, password, _logger);
        await dsm.LoginAsync(ct);
        try
        {
            return await InstallAsync(dsm, target, ct);
        }
        finally
        {
            using var logoutTimeout = new CancellationTokenSource(LogoutTimeout);
            await client.LogoutAsync(dsm.Session, logoutTimeout.Token);
        }
    }

    /// <summary>Splits the Services option on commas, semicolons and newlines.</summary>
    internal static IReadOnlyList<string> ParseServiceNames(string raw) =>
        raw.Split([',', ';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private sealed record Target(
        string Description,
        IReadOnlyList<string> Services,
        bool AsDefault,
        DateTimeOffset NotAfter,
        DsmCertificateMaterial Material);

    private async Task<InstallResult> InstallAsync(Connection dsm, Target target, CancellationToken ct)
    {
        var before = await dsm.ListAsync(ct);
        RequireKnownServices(before, target);
        var existing = FindByDescription(before, target.Description);
        var asDefault = target.AsDefault || existing?.IsDefault == true;

        var (certs, imported, confirmed) = await ImportAsync(dsm, before, existing, target, asDefault, ct);
        var bindings = await BindServicesAsync(dsm, certs, imported, target, ct);

        var detail = $"{(existing is null ? "Imported into" : "Replaced in")} DSM as '{target.Description}'"
            + bindings.Describe()
            + (confirmed ? "" : "; DSM dropped the connection and the replacement could not be confirmed " +
                "(same expiry as before) — check Control Panel → Security → Certificate");
        return InstallResult.Ok(detail);
    }

    /// <summary>
    /// Imports or replaces the certificate. When DSM answers, its answer is
    /// authoritative. When the connection drops or the session ends mid-call, the
    /// outcome is established from the list: a replacement must show the new expiry,
    /// a new import must appear under an id that did not exist before.
    /// </summary>
    private async Task<(IReadOnlyList<DsmCertificate> Certs, DsmCertificate Imported, bool Confirmed)> ImportAsync(
        Connection dsm, IReadOnlyList<DsmCertificate> before, DsmCertificate? existing, Target target,
        bool asDefault, CancellationToken ct)
    {
        string? id = null;
        var interrupted = await dsm.TryMutateAsync("import", async (client, session) =>
            id = await client.ImportCertificateAsync(session, target.Material, existing?.Id, target.Description, asDefault, ct),
            ct);

        if (!interrupted)
        {
            // DSM restarts its web server after an import; wait for it to list the result.
            var (certs, imported) = await WaitForAsync(dsm, ct, "the imported certificate",
                list => list.FirstOrDefault(c => c.Id == id));
            Log(existing, target, imported);
            return (certs, imported, true);
        }

        if (existing is not null)
        {
            var unchangedExpiry = existing.ValidTill is { } old && (old - target.NotAfter).Duration() <= ExpiryTolerance;
            var (certs, imported) = await WaitForAsync(dsm, ct, "the replaced certificate", list =>
                list.FirstOrDefault(c => c.Id == existing.Id && c.ValidTill is { } till
                    && (till - target.NotAfter).Duration() <= ExpiryTolerance));
            if (unchangedExpiry)
            {
                _logger.LogWarning("Could not confirm DSM replaced '{Description}': the new certificate has the same expiry",
                    target.Description);
            }
            Log(existing, target, imported);
            return (certs, imported, !unchangedExpiry);
        }

        var knownIds = before.Select(c => c.Id).ToHashSet(StringComparer.Ordinal);
        var (allCerts, created) = await WaitForAsync(dsm, ct, "the imported certificate", list =>
        {
            var fresh = list.Where(c => !knownIds.Contains(c.Id) && c.Description == target.Description).ToList();
            return fresh.Count <= 1 ? fresh.SingleOrDefault() : throw DuplicateDescription(fresh.Count, target.Description);
        });
        Log(existing, target, created);
        return (allCerts, created, true);
    }

    private void Log(DsmCertificate? existing, Target target, DsmCertificate imported) =>
        _logger.LogInformation("{Action} DSM certificate '{Description}' (id {Id})",
            existing is null ? "Imported" : "Replaced", target.Description, imported.Id);

    private static void RequireKnownServices(IReadOnlyList<DsmCertificate> certs, Target target)
    {
        if (target.Services is [AllServices] or [])
        {
            return;
        }
        var known = AllServiceNames(certs);
        var missing = target.Services.Where(name => !known.Any(k => NameMatches(k, name))).ToList();
        if (missing.Count > 0)
        {
            throw new InvalidOperationException(
                $"Synology DSM installer: DSM has no service named {string.Join(", ", missing.Select(m => $"'{m}'"))}; " +
                $"nothing was changed. Available: {string.Join(", ", known)}.");
        }
    }

    private static DsmCertificate? FindByDescription(IReadOnlyList<DsmCertificate> certs, string description)
    {
        var matches = certs.Where(c => c.Description == description).ToList();
        return matches.Count switch
        {
            0 => null,
            1 => matches[0],
            _ => throw DuplicateDescription(matches.Count, description),
        };
    }

    private static InvalidOperationException DuplicateDescription(int count, string description) => new(
        $"Synology DSM installer: {count} DSM certificates are described '{description}'. " +
        "Rename or delete the extras in DSM (Control Panel → Security → Certificate) so renewals know which to replace.");

    /// <summary>Moves the requested services onto the imported certificate. Services
    /// already on it are left alone, so renewals make no changes.</summary>
    private async Task<BindingReport> BindServicesAsync(
        Connection dsm, IReadOnlyList<DsmCertificate> certs, DsmCertificate imported, Target target, CancellationToken ct)
    {
        if (target.Services.Count == 0)
        {
            return new BindingReport([], [], AllServiceNames(certs));
        }

        var bindAll = target.Services is [AllServices];
        var selected = certs
            .SelectMany(c => c.Services.Select(s => (Cert: c, Service: s)))
            .Where(x => bindAll || target.Services.Any(name => NameMatches(x.Service.DisplayName, name)))
            .ToList();

        var moves = selected.Where(x => x.Cert.Id != imported.Id).Select(x => (x.Service, x.Cert.Id)).ToList();
        if (moves.Count > 0)
        {
            if (bindAll)
            {
                _logger.LogInformation("'*' takes {Services} from other DSM certificates",
                    string.Join(", ", moves.Select(m => m.Service.DisplayName)));
            }
            await dsm.TryMutateAsync("service binding",
                (client, session) => client.SetServicesAsync(session, moves, imported.Id, ct), ct);

            var wanted = moves.Select(m => ServiceKey(m.Service)).ToHashSet(StringComparer.Ordinal);
            await WaitForAsync(dsm, ct, "the service bindings", list =>
            {
                var onImported = list.Where(c => c.Id == imported.Id).SelectMany(c => c.Services).Select(ServiceKey);
                return wanted.IsSubsetOf(onImported) ? imported : null;
            });
            _logger.LogInformation("Bound {Services} to DSM certificate '{Description}'",
                string.Join(", ", moves.Select(m => m.Service.DisplayName)), target.Description);
        }

        return new BindingReport(
            Moved: Names(moves.Select(m => m.Service)),
            AlreadyBound: Names(selected.Where(x => x.Cert.Id == imported.Id).Select(x => x.Service)),
            Available: []);
    }

    /// <summary>What the service step did, for the run result.</summary>
    private sealed record BindingReport(
        IReadOnlyList<string> Moved, IReadOnlyList<string> AlreadyBound, IReadOnlyList<string> Available)
    {
        public string Describe()
        {
            if (Moved.Count == 0 && AlreadyBound.Count == 0)
            {
                return "; no services were moved (none requested)"
                    + (Available.Count > 0 ? $" — DSM services: {string.Join(", ", Available)}" : "");
            }
            return (Moved.Count > 0 ? $"; moved {string.Join(", ", Moved)}" : "")
                + (AlreadyBound.Count > 0 ? $"; already on it: {string.Join(", ", AlreadyBound)}" : "");
        }
    }

    private static IReadOnlyList<string> Names(IEnumerable<DsmCertificateService> services) =>
        services.Select(s => s.DisplayName).Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase).ToList();

    private static IReadOnlyList<string> AllServiceNames(IReadOnlyList<DsmCertificate> certs) =>
        Names(certs.SelectMany(c => c.Services));

    /// <summary>
    /// DSM's own screens and its API name some services differently: Control Panel →
    /// Security → Certificate → Settings lists the DSM web interface as "System
    /// default", the API as "DSM Desktop Service". Either name is accepted.
    /// </summary>
    private static readonly Dictionary<string, string> DialogNameToApiName = new(StringComparer.OrdinalIgnoreCase)
    {
        ["System default"] = "DSM Desktop Service",
    };

    internal static bool NameMatches(string apiName, string requested) =>
        string.Equals(apiName, requested, StringComparison.OrdinalIgnoreCase)
        || (DialogNameToApiName.TryGetValue(requested, out var alias)
            && string.Equals(apiName, alias, StringComparison.OrdinalIgnoreCase));

    /// <summary>Polls DSM's certificate list until <paramref name="match"/> finds what it
    /// is looking for, riding out the web-server restart DSM performs after changes.</summary>
    private async Task<(IReadOnlyList<DsmCertificate> Certs, DsmCertificate Match)> WaitForAsync(
        Connection dsm, CancellationToken ct, string what, Func<IReadOnlyList<DsmCertificate>, DsmCertificate?> match)
    {
        for (var attempt = 1; attempt <= VerifyAttempts; attempt++)
        {
            try
            {
                var certs = await dsm.ListAsync(ct);
                if (match(certs) is { } found)
                {
                    return (certs, found);
                }
            }
            catch (DsmApiException ex) when (ex.Kind == DsmErrorKind.Transport)
            {
                _logger.LogDebug("DSM not answering yet while verifying {What}: {Message}", what, ex.Message);
            }
            await Task.Delay(_pollInterval, ct);
        }
        throw new InvalidOperationException(
            $"Synology DSM installer: DSM did not show {what} after {VerifyAttempts} checks. " +
            "Check Control Panel → Security → Certificate.");
    }

    // Display name is part of the key so entries DSM reports with blank ids can't
    // collide into a false "already bound" match.
    private static string ServiceKey(DsmCertificateService service) =>
        $"{service.Subscriber}|{service.Service}|{service.DisplayName}";

    /// <summary>
    /// The signed-in DSM session for one install. DSM can end the session when it
    /// restarts its web server; reads sign in again (once per call) and continue,
    /// changes report the interruption so the caller verifies instead of repeating.
    /// </summary>
    private sealed class Connection(DsmApiClient client, string account, string password, ILogger logger)
    {
        public DsmSession Session { get; private set; } = null!;

        public async Task LoginAsync(CancellationToken ct) =>
            Session = await client.LoginAsync(account, password, ct);

        public async Task<IReadOnlyList<DsmCertificate>> ListAsync(CancellationToken ct)
        {
            try
            {
                return await client.ListCertificatesAsync(Session, ct);
            }
            catch (DsmApiException ex) when (ex.Kind == DsmErrorKind.SessionExpired)
            {
                logger.LogInformation("DSM session ended (code {Code}); signing in again", ex.Code);
                await LoginAsync(ct);
                return await client.ListCertificatesAsync(Session, ct);
            }
        }

        /// <summary>Runs a change. Returns true if it was interrupted (connection dropped
        /// or session ended) and its outcome must be verified; DSM's own refusals throw.</summary>
        public async Task<bool> TryMutateAsync(
            string what, Func<DsmApiClient, DsmSession, Task> change, CancellationToken ct)
        {
            try
            {
                await change(client, Session);
                return false;
            }
            catch (DsmApiException ex) when (ex.Kind == DsmErrorKind.Transport)
            {
                logger.LogWarning("Connection to DSM dropped during {What} ({Message}); verifying", what, ex.Message);
                return true;
            }
            catch (DsmApiException ex) when (ex.Kind == DsmErrorKind.SessionExpired)
            {
                logger.LogWarning("DSM session ended during {What} (code {Code}); signing in again to verify", what, ex.Code);
                await LoginAsync(ct);
                return true;
            }
        }
    }
}
