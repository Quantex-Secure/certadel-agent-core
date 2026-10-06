using System.Text;
using System.Text.Json.Nodes;

using AcmeManager.Core.Acme;
using AcmeManager.Core.Security;
using AcmeManager.Core.Storage;
using AcmeManager.Core.Storage.Entities;

using Microsoft.EntityFrameworkCore;

namespace AcmeManager.Service.Migration.AcmeSh;

internal sealed record AcmeShRenewalPreview(
    string Name, string Identifiers, string Validation, string InstallPath, IReadOnlyList<string> Notes);

internal sealed record AcmeShImportPreview(
    string? Error,
    string? Home,
    IReadOnlyList<string> CaDirectories,
    IReadOnlyList<AcmeShRenewalPreview> Renewals)
{
    public int RenewalCount => Renewals.Count;
    public int WithNotes => Renewals.Count(r => r.Notes.Count > 0);
}

internal sealed record AcmeShImportOutcome(string Name, string Status);

internal sealed record AcmeShImportResult(
    string? Error, int Imported, int Skipped, IReadOnlyList<AcmeShImportOutcome> Items);

/// <summary>
/// The operator's import choices: installer + store, and — per acme.sh DNS method —
/// which configured DNS provider profile (by id) to snapshot. Secrets live inside
/// those profiles, never here.
/// </summary>
internal sealed record AcmeShImportChoices(
    string InstallerPluginId = "installer.haproxy",
    string HaProxyCertDir = "/etc/haproxy/certs",
    string StorePluginId = "",
    string StorePath = "",
    Guid? DnsProfileId = null);

/// <summary>
/// Imports an acme.sh installation into acme-manager. <see cref="PreviewAsync"/> only
/// reads files + DNS provider profiles (safe anywhere); <see cref="ApplyAsync"/> also
/// registers the acme.sh account key with the CA (idempotent) and writes the renewals.
/// DNS credentials come from the selected provider profile, never from acme.sh.
/// </summary>
internal sealed class AcmeShImportService(
    AcmeManagerDbContext db,
    ISecretProtector protector,
    IAcmeClient acme,
    ILogger<AcmeShImportService> logger)
{
    public async Task<AcmeShImportPreview> PreviewAsync(
        string? path, AcmeShImportChoices? choices, CancellationToken ct)
    {
        var homes = AcmeShReader.ResolveHomes(path);
        if (homes.Count == 0)
        {
            var where = string.IsNullOrWhiteSpace(path)
                ? "Looked in: " + string.Join(", ", AcmeShReader.DefaultLocations())
                : $"Path not found: {path}";
            return new AcmeShImportPreview($"No acme.sh installation found. {where}", null, [], []);
        }

        var ctx = await BuildContextAsync(choices ?? new AcmeShImportChoices(), ct);
        var confs = AcmeShReader.ReadRenewals(homes);

        var previews = confs.Select(c =>
        {
            var mapped = AcmeShMapper.Map(c, ctx);
            return new AcmeShRenewalPreview(
                c.Domain,
                string.Join(", ", new[] { c.Domain }.Concat(c.AltNames)),
                PluginIdOf(mapped.ValidationJson),
                ctx.InstallerPluginId == "installer.haproxy" ? $"{ctx.HaProxyCertDir.TrimEnd('/')}/{c.Domain}.pem" : "(no installer)",
                mapped.Notes);
        }).ToList();

        var cas = AcmeShReader.ReadAccounts(homes).Select(a => a.DirectoryUrl).ToList();
        return new AcmeShImportPreview(null, string.Join(", ", homes), cas, previews);
    }

    public async Task<AcmeShImportResult> ApplyAsync(
        string? path,
        string? accountName,
        AcmeShImportChoices choices,
        IReadOnlyCollection<string>? selectedDomains,
        CancellationToken ct)
    {
        var homes = AcmeShReader.ResolveHomes(path);
        if (homes.Count == 0)
        {
            return new AcmeShImportResult("acme.sh installation not found.", 0, 0, []);
        }

        var ctx = await BuildContextAsync(choices, ct);
        var confs = AcmeShReader.ReadRenewals(homes);
        if (selectedDomains is { Count: > 0 })
        {
            var pick = new HashSet<string>(selectedDomains, StringComparer.OrdinalIgnoreCase);
            confs = confs.Where(c => pick.Contains(c.Domain)).ToList();
        }
        var shAccounts = AcmeShReader.ReadAccounts(homes);

        Account? forced = null;
        if (!string.IsNullOrEmpty(accountName))
        {
            forced = await db.Accounts.FirstOrDefaultAsync(a => a.Name.ToLower() == accountName.ToLower(), ct);
            if (forced is null)
            {
                return new AcmeShImportResult($"No account named '{accountName}'.", 0, 0, []);
            }
        }

        var byDirectory = new Dictionary<string, Account>(StringComparer.OrdinalIgnoreCase);
        var items = new List<AcmeShImportOutcome>();
        var imported = 0;
        var skipped = 0;

        foreach (var conf in confs)
        {
            var account = forced ?? await ResolveAccountAsync(conf.DirectoryUrl, shAccounts, byDirectory, ct);
            if (account is null)
            {
                items.Add(new AcmeShImportOutcome(conf.Domain, $"skipped — no account for {conf.DirectoryUrl}"));
                skipped++;
                continue;
            }

            var mapped = AcmeShMapper.Map(conf, ctx);
            if (await db.Renewals.AnyAsync(x => x.Name == mapped.Name, ct))
            {
                items.Add(new AcmeShImportOutcome(mapped.Name, "skipped — a renewal with this name already exists"));
                skipped++;
                continue;
            }

            db.Renewals.Add(new Renewal
            {
                Name = mapped.Name,
                AccountId = account.Id,
                RenewalWindowDays = 30,
                SourceJson = mapped.SourceJson,
                ValidationJson = mapped.ValidationJson,
                StoresJson = mapped.StoresJson,
                InstallationsJson = mapped.InstallationsJson,
                Enabled = true,
            });
            await db.SaveChangesAsync(ct);

            items.Add(new AcmeShImportOutcome(mapped.Name, "imported"));
            imported++;
            logger.LogInformation("acme.sh import: '{Name}' imported", mapped.Name);
        }

        return new AcmeShImportResult(null, imported, skipped, items);
    }

    /// <summary>Resolves the chosen DNS provider profiles (by id) into snapshots.</summary>
    private async Task<AcmeShMapContext> BuildContextAsync(AcmeShImportChoices choices, CancellationToken ct)
    {
        DnsProfileSnapshot? profile = null;
        if (choices.DnsProfileId is { } id)
        {
            var p = await db.DnsProviders.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
            if (p is not null)
            {
                profile = new DnsProfileSnapshot(p.PluginId, p.OptionsJson);
            }
        }
        return new AcmeShMapContext(
            InstallerPluginId: choices.InstallerPluginId,
            HaProxyCertDir: string.IsNullOrWhiteSpace(choices.HaProxyCertDir) ? "/etc/haproxy/certs" : choices.HaProxyCertDir.Trim(),
            StorePluginId: choices.StorePluginId,
            StorePath: choices.StorePath,
            DnsProfile: profile);
    }

    private async Task<Account?> ResolveAccountAsync(
        string directoryUrl, IReadOnlyList<AcmeShAccount> shAccounts, Dictionary<string, Account> cache, CancellationToken ct)
    {
        if (cache.TryGetValue(directoryUrl, out var cached))
        {
            return cached;
        }

        var existing = await db.Accounts.FirstOrDefaultAsync(a => a.DirectoryUrl == directoryUrl, ct);
        if (existing is not null)
        {
            cache[directoryUrl] = existing;
            return existing;
        }

        var sh = shAccounts.FirstOrDefault(a => string.Equals(a.DirectoryUrl, directoryUrl, StringComparison.OrdinalIgnoreCase));
        if (sh is null)
        {
            return null;
        }

        AcmeAccount registered;
        try
        {
            registered = await acme.CreateAccountAsync(
                new AcmeAccount(Guid.NewGuid(), new Uri(sh.DirectoryUrl), "", new AcmeAccountKey(sh.KeyPem), KeyId: null),
                eab: null, ct);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not register acme.sh account key for {Directory}", sh.DirectoryUrl);
            return null;
        }

        var account = new Account
        {
            Name = await UniqueAccountNameAsync(DeriveAccountName(sh.DirectoryUrl), ct),
            DirectoryUrl = sh.DirectoryUrl,
            ContactEmail = registered.ContactEmail,
            AccountKeyEncrypted = protector.Protect(Encoding.UTF8.GetBytes(sh.KeyPem)),
            KeyId = registered.KeyId?.ToString(),
            RegisteredAt = DateTimeOffset.UtcNow,
        };
        db.Accounts.Add(account);
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Imported acme.sh account for {Directory} as '{Name}'", sh.DirectoryUrl, account.Name);

        cache[directoryUrl] = account;
        return account;
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
        return host.Contains("staging", StringComparison.OrdinalIgnoreCase)
            ? "Let's Encrypt Staging (acme.sh)"
            : "Let's Encrypt (acme.sh)";
    }

    private static string PluginIdOf(string wireJson)
    {
        try
        {
            return JsonNode.Parse(wireJson)?["pluginId"]?.ToString() ?? "?";
        }
        catch
        {
            return "?";
        }
    }
}