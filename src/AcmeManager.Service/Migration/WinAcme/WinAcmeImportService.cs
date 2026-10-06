using System.Text.Json.Nodes;

using AcmeManager.Core.Security;
using AcmeManager.Core.Storage;
using AcmeManager.Core.Storage.Entities;

using Microsoft.EntityFrameworkCore;

namespace AcmeManager.Service.Migration.WinAcme;

internal sealed record WinAcmeRenewalPreview(
    string Name,
    string SourcePluginId,
    string ValidationPluginId,
    string StorePluginIds,
    string InstallationPluginIds,
    IReadOnlyList<string> SecretNames,
    IReadOnlyList<string> Notes);

internal sealed record WinAcmeCaFolderPreview(
    string Path,
    string AccountKeyDescription,
    string AccountUrl,
    IReadOnlyList<WinAcmeRenewalPreview> Renewals);

internal sealed record WinAcmeImportPreview(
    string? Error,
    string? BaseDir,
    IReadOnlyList<WinAcmeCaFolderPreview> CaFolders)
{
    public int RenewalCount => CaFolders.Sum(c => c.Renewals.Count);

    public int WithNotes => CaFolders.Sum(c => c.Renewals.Count(r => r.Notes.Count > 0));
}

internal sealed record WinAcmeImportOutcome(string Name, string Status);

internal sealed record WinAcmeImportResult(
    string? Error,
    int Imported,
    int Skipped,
    IReadOnlyList<WinAcmeImportOutcome> Items);

/// <summary>
/// The win-acme import engine, decoupled from the CLI so the agent's web UI can
/// drive it too. <see cref="Preview"/> only reads the win-acme files (safe
/// anywhere); <see cref="ApplyAsync"/> writes accounts/secrets/DNS profiles/
/// renewals into the agent database. DPAPI-protected win-acme secrets can only
/// be decrypted on the machine (and user context) that ran win-acme — both the
/// CLI and the UI inherit that constraint.
/// </summary>
internal sealed class WinAcmeImportService(
    AcmeManagerDbContext db,
    ISecretProtector protector,
    ILogger<WinAcmeImportService> logger)
{
    public WinAcmeImportPreview Preview(
        string? path, string? azureSecretName = null, string? certStoreName = null, string? certStoreLocation = null)
    {
        var baseDir = WinAcmeStore.ResolveBaseDir(path);
        if (baseDir is null)
        {
            var error = string.IsNullOrWhiteSpace(path)
                ? "No win-acme configuration found. Looked in: " + string.Join(", ", WinAcmeStore.DefaultLocations())
                : $"Path not found: {path}";
            return new WinAcmeImportPreview(error, null, []);
        }

        var config = WinAcmeStore.Read(baseDir);
        var context = BuildMapContext(azureSecretName, certStoreName, certStoreLocation);
        var index = 0;
        var folders = new List<WinAcmeCaFolderPreview>();
        foreach (var ca in config.CaFolders)
        {
            var renewals = ca.Renewals
                .Select(r => ToPreview(WinAcmeMapper.Map(r, index++, context)))
                .ToList();
            folders.Add(new WinAcmeCaFolderPreview(
                ca.Path,
                DescribeSigner(ca.SignerRaw),
                ca.Registration?["Kid"]?.ToString() ?? ca.Registration?["Location"]?.ToString() ?? "(unknown)",
                renewals));
        }
        return new WinAcmeImportPreview(null, config.BaseDir, folders);
    }

    public async Task<WinAcmeImportResult> ApplyAsync(
        string? path,
        string? accountName,
        bool noAccountImport,
        CancellationToken ct,
        string? azureSecretName = null,
        string? certStoreName = null,
        string? certStoreLocation = null,
        IReadOnlyCollection<string>? selectedNames = null)
    {
        var selection = selectedNames is { Count: > 0 }
            ? new HashSet<string>(selectedNames, StringComparer.OrdinalIgnoreCase)
            : null;
        var baseDir = WinAcmeStore.ResolveBaseDir(path);
        if (baseDir is null)
        {
            return new WinAcmeImportResult("win-acme configuration not found.", 0, 0, []);
        }

        var config = WinAcmeStore.Read(baseDir);
        var context = BuildMapContext(azureSecretName, certStoreName, certStoreLocation);
        var items = new List<WinAcmeImportOutcome>();
        var imported = 0;
        var skipped = 0;
        var index = 0;

        foreach (var ca in config.CaFolders)
        {
            var (account, error) = await ResolveAccountAsync(ca, accountName, noAccountImport, ct);
            if (account is null)
            {
                return new WinAcmeImportResult(error ?? "Could not resolve an account.", imported, skipped, items);
            }
            logger.LogInformation("win-acme import: CA folder {Path} → account '{Account}'", ca.Path, account.Name);

            foreach (var r in ca.Renewals)
            {
                var mapped = WinAcmeMapper.Map(r, index++, context);
                if (selection is not null && !selection.Contains(mapped.Name))
                {
                    continue; // not selected for import
                }
                if (await db.Renewals.AnyAsync(x => x.Name == mapped.Name, ct))
                {
                    items.Add(new WinAcmeImportOutcome(mapped.Name, "skipped — a renewal with this name already exists"));
                    skipped++;
                    continue;
                }
                await PersistAsync(account, mapped, ct);
                items.Add(new WinAcmeImportOutcome(mapped.Name, "imported"));
                imported++;
                logger.LogInformation("win-acme import: '{Name}' imported", mapped.Name);
            }
        }

        return new WinAcmeImportResult(null, imported, skipped, items);
    }

    /// <summary>
    /// The account a CA folder's renewals attach to. Order: explicit name; else
    /// import win-acme's own account key (same key → same registered ACME
    /// account); else fall back to the single existing account.
    /// </summary>
    private async Task<(Account? Account, string? Error)> ResolveAccountAsync(
        WinAcmeCaFolder ca,
        string? accountName,
        bool noAccountImport,
        CancellationToken ct)
    {
        if (accountName is not null)
        {
            return await PickAccountAsync(accountName, ct);
        }

        if (!noAccountImport)
        {
            ImportedAccount? imp = null;
            try
            {
                imp = WinAcmeAccount.Convert(ca.SignerRaw, ca.Registration);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "win-acme account-key import failed; falling back to an existing account");
            }

            if (imp is not null)
            {
                var existing = await db.Accounts.FirstOrDefaultAsync(a => a.KeyId == imp.KeyId, ct);
                if (existing is not null)
                {
                    return (existing, null);
                }

                var name = await UniqueAccountNameAsync(DeriveAccountName(imp.DirectoryUrl), ct);
                var account = new Account
                {
                    Name = name,
                    DirectoryUrl = imp.DirectoryUrl,
                    ContactEmail = imp.ContactEmail,
                    AccountKeyEncrypted = protector.Protect(System.Text.Encoding.UTF8.GetBytes(imp.Pem)),
                    KeyId = imp.KeyId,
                    RegisteredAt = DateTimeOffset.UtcNow,
                };
                db.Accounts.Add(account);
                await db.SaveChangesAsync(ct);
                logger.LogInformation("Imported win-acme account {KeyId} as '{Name}'", imp.KeyId, name);
                return (account, null);
            }
        }

        return await PickAccountAsync(accountName: null, ct);
    }

    private async Task<(Account? Account, string? Error)> PickAccountAsync(string? accountName, CancellationToken ct)
    {
        var accounts = await db.Accounts.ToListAsync(ct);
        if (accounts.Count == 0)
        {
            return (null, "No acme-manager account exists yet. Create one first (Settings → ACME Accounts).");
        }
        if (accountName is not null)
        {
            var match = accounts.FirstOrDefault(a => a.Name.Equals(accountName, StringComparison.OrdinalIgnoreCase));
            return match is not null
                ? (match, null)
                : (null, $"No account named '{accountName}'. Available: {string.Join(", ", accounts.Select(a => a.Name))}");
        }
        if (accounts.Count == 1)
        {
            return (accounts[0], null);
        }
        return (null, $"Multiple accounts exist; pick one: {string.Join(", ", accounts.Select(a => a.Name))}");
    }

    private async Task PersistAsync(Account account, MappedRenewal m, CancellationToken ct)
    {
        foreach (var s in m.Secrets)
        {
            if (!await db.Secrets.AnyAsync(x => x.Name == s.Name, ct))
            {
                db.Secrets.Add(new Secret
                {
                    Name = s.Name,
                    EncryptedValue = protector.Protect(System.Text.Encoding.UTF8.GetBytes(s.Value)),
                });
            }
        }

        if (m.DnsProfile is { } p && !await db.DnsProviders.AnyAsync(x => x.Name == p.Name, ct))
        {
            db.DnsProviders.Add(new DnsProvider { Name = p.Name, PluginId = p.PluginId, OptionsJson = p.Options.ToJsonString() });
        }

        db.Renewals.Add(new Renewal
        {
            Name = m.Name,
            AccountId = account.Id,
            RenewalWindowDays = 30,
            SourceJson = m.SourceJson,
            ValidationJson = m.ValidationJson,
            StoresJson = m.StoresJson,
            InstallationsJson = m.InstallationsJson,
            Enabled = true,
        });

        await db.SaveChangesAsync(ct);
    }

    private async Task<string> UniqueAccountNameAsync(string baseName, CancellationToken ct)
    {
        var name = baseName;
        var n = 2;
        while (await db.Accounts.AnyAsync(a => a.Name == name, ct))
        {
            name = $"{baseName} ({n++})";
        }
        return name;
    }

    private static string DeriveAccountName(string directoryUrl)
    {
        var host = new Uri(directoryUrl).Host;
        if (host.Contains("staging", StringComparison.OrdinalIgnoreCase)
            && host.Contains("letsencrypt", StringComparison.OrdinalIgnoreCase))
        {
            return "Let's Encrypt Staging (imported)";
        }
        if (host.Contains("letsencrypt", StringComparison.OrdinalIgnoreCase))
        {
            return "Let's Encrypt (imported)";
        }
        return $"{host} (imported)";
    }

    /// <summary>
    /// Builds the map context. win-acme stores IIS sites by numeric id and binds
    /// "(any host)" renewals at runtime; acme-manager needs the site NAME and an
    /// explicit host. When running on the IIS machine (the normal case — DPAPI
    /// requires it anyway), snapshot id → name and name → primary host so imported
    /// renewals are runnable as-is. The Azure secret is referenced, never imported.
    /// </summary>
    private WinAcmeMapContext BuildMapContext(string? azureSecretName, string? certStoreName, string? certStoreLocation)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new WinAcmeMapContext(
                AzureSecretName: azureSecretName, CertStoreName: certStoreName, CertStoreLocation: certStoreLocation);
        }
        try
        {
            using var serverManager = new Microsoft.Web.Administration.ServerManager();
            var nameById = new Dictionary<string, string>(StringComparer.Ordinal);
            var hostByName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var site in serverManager.Sites)
            {
                nameById[site.Id.ToString()] = site.Name;
                // Primary host = first binding (https preferred) that carries a host header.
                var host = site.Bindings
                    .Where(b => !string.IsNullOrWhiteSpace(b.Host))
                    .OrderByDescending(b => b.Protocol == "https")
                    .Select(b => b.Host)
                    .FirstOrDefault();
                if (!string.IsNullOrEmpty(host))
                {
                    hostByName[site.Name] = host;
                }
            }
            return new WinAcmeMapContext(
                ResolveSiteName: id => nameById.TryGetValue(id, out var name) ? name : null,
                ResolveSiteHost: name => hostByName.TryGetValue(name, out var host) ? host : null,
                AzureSecretName: azureSecretName,
                CertStoreName: certStoreName,
                CertStoreLocation: certStoreLocation);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "IIS is not readable here, so win-acme site ids/hosts can't be resolved; set site/host manually after import");
            return new WinAcmeMapContext(
                AzureSecretName: azureSecretName, CertStoreName: certStoreName, CertStoreLocation: certStoreLocation);
        }
    }

    private static WinAcmeRenewalPreview ToPreview(MappedRenewal m) => new(
        m.Name,
        PluginIdOf(m.SourceJson),
        PluginIdOf(m.ValidationJson),
        PluginIdsOf(m.StoresJson),
        PluginIdsOf(m.InstallationsJson),
        m.Secrets.Select(s => s.Name).ToList(),
        m.Notes);

    private static string DescribeSigner(string? signerRaw)
    {
        if (signerRaw is null)
        {
            return "(no Signer_v2 file)";
        }
        var dec = WinAcmeProtectedString.Decode(signerRaw);
        if (dec.Kind != WinAcmeProtectedString.Kind.Plain || dec.Value is null)
        {
            return $"present but not readable here ({dec.Note ?? dec.Kind.ToString()})";
        }
        try
        {
            var o = JsonNode.Parse(dec.Value) as JsonObject;
            return $"KeyType={o?["KeyType"]}, export length={o?["KeyExport"]?.ToString().Length ?? 0}";
        }
        catch
        {
            return "present (unrecognised inner format)";
        }
    }

    private static string PluginIdOf(string wireSingle)
    {
        try
        {
            return (JsonNode.Parse(wireSingle) as JsonObject)?["pluginId"]?.ToString() ?? "?";
        }
        catch
        {
            return "?";
        }
    }

    private static string PluginIdsOf(string wireList)
    {
        try
        {
            var arr = JsonNode.Parse(wireList) as JsonArray;
            if (arr is null || arr.Count == 0)
            {
                return "(none)";
            }
            return string.Join(", ", arr.Select(e => (e as JsonObject)?["pluginId"]?.ToString() ?? "?"));
        }
        catch
        {
            return "?";
        }
    }
}