using AcmeManager.Core.Acme;
using AcmeManager.Core.Security;
using AcmeManager.Core.Storage;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AcmeManager.Service.Migration.AcmeSh;

/// <summary>
/// <c>AcmeManager.Service import-acmesh [--path DIR] [--apply] [--account NAME]
/// [--dns-profile "Azure-Prod"] [--installer installer.haproxy|none]
/// [--haproxy-cert-dir DIR] [--store store.pem] [--only d1,d2]</c>
///
/// Run this ON the Linux host that has acme.sh installed. The console front-end over
/// <see cref="AcmeShImportService"/> — the same engine the web UI's import page
/// drives — so migrations are scriptable. DNS credentials come from your configured
/// DNS provider profiles (matched by type). Without <c>--apply</c> it changes nothing.
/// </summary>
internal static class AcmeShImport
{
    public static async Task<int> RunAsync(string[] args)
    {
        var apply = args.Contains("--apply", StringComparer.OrdinalIgnoreCase);
        var path = ArgValue(args, "--path");
        var accountName = ArgValue(args, "--account");
        var installer = ArgValue(args, "--installer") ?? "installer.haproxy";
        if (installer.Equals("none", StringComparison.OrdinalIgnoreCase)) installer = "";
        var haProxyCertDir = ArgValue(args, "--haproxy-cert-dir") ?? "/etc/haproxy/certs";
        var store = ArgValue(args, "--store") ?? "";
        var profileName = ArgValue(args, "--dns-profile");
        var only = ArgValue(args, "--only")
            ?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        Console.WriteLine("== acme-manager: import from acme.sh ==");

        using var host = BuildHost();
        using var scope = host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();
        var protector = scope.ServiceProvider.GetRequiredService<ISecretProtector>();
        var acme = scope.ServiceProvider.GetRequiredService<IAcmeClient>();
        var service = new AcmeShImportService(
            db, protector, acme, scope.ServiceProvider.GetRequiredService<ILogger<AcmeShImportService>>());

        Guid? dnsProfileId = null;
        if (!string.IsNullOrEmpty(profileName))
        {
            var match = (await db.DnsProviders.AsNoTracking().ToListAsync())
                .FirstOrDefault(p => p.Name.Equals(profileName, StringComparison.OrdinalIgnoreCase));
            if (match is null)
            {
                Console.Error.WriteLine($"No DNS provider profile named '{profileName}'. Create one under Settings > DNS Providers.");
                return 2;
            }
            dnsProfileId = match.Id;
        }

        var choices = new AcmeShImportChoices(installer, haProxyCertDir, store, "", dnsProfileId);
        var preview = await service.PreviewAsync(path, choices, default);
        if (preview.Error is not null)
        {
            Console.Error.WriteLine(preview.Error);
            Console.Error.WriteLine("Pass --path <acme.sh home> (default /root/.acme.sh).");
            return 2;
        }

        Console.WriteLine($"Source: {preview.Home}");
        Console.WriteLine($"Found {preview.RenewalCount} renewal(s); CA account(s): {string.Join(", ", preview.CaDirectories)}");
        Console.WriteLine(apply
            ? "Mode:   APPLY (writing to acme-manager)\n"
            : "Mode:   DRY RUN (no changes; re-run with --apply to import)\n");

        foreach (var r in preview.Renewals)
        {
            Console.WriteLine($"  • {r.Name}  [{r.Identifiers}]");
            Console.WriteLine($"      validation:  {r.Validation}");
            Console.WriteLine($"      installs to: {r.InstallPath}");
            foreach (var n in r.Notes)
            {
                Console.WriteLine($"      ⚠ {n}");
            }
        }

        var imported = 0;
        var skipped = 0;
        if (apply && preview.RenewalCount > 0)
        {
            Directory.CreateDirectory(DataPaths.Root);
            await db.Database.MigrateAsync();
            Console.WriteLine();

            var result = await service.ApplyAsync(path, accountName, choices, only, default);
            foreach (var item in result.Items)
            {
                Console.WriteLine($"  • {item.Name} → {item.Status}");
            }
            if (result.Error is not null)
            {
                Console.Error.WriteLine(result.Error);
                return 3;
            }
            imported = result.Imported;
            skipped = result.Skipped;
            Console.WriteLine();
        }

        Console.WriteLine("== Summary ==");
        Console.WriteLine($"Renewals seen:      {preview.RenewalCount}");
        Console.WriteLine($"With review notes:   {preview.WithNotes}");
        if (apply)
        {
            Console.WriteLine($"Imported:           {imported}");
            Console.WriteLine($"Skipped (existing): {skipped}");
            Console.WriteLine("\nDone. Items shown as manual had no matching DNS provider profile — pass " +
                "--dns-profiles or pick one in the UI, then re-import. acme.sh's own renewal for these " +
                "domains is still active; disable it (acme.sh --remove -d <domain>) once acme-manager is confirmed.");
        }
        else
        {
            Console.WriteLine("\nThis was a preview. Re-run with --apply to write these into acme-manager.");
        }
        return 0;
    }

    private static IHost BuildHost()
    {
        var hb = Host.CreateApplicationBuilder();
        hb.Logging.ClearProviders();
        var databaseFile = hb.Configuration["Storage:DatabaseFile"] ?? DataPaths.DatabaseFile;
        Console.WriteLine($"Database: {databaseFile}");
        hb.Services.AddDbContextFactory<AcmeManagerDbContext>(o => o.UseSqlite($"Data Source={databaseFile}"));
        hb.Services.AddScoped(sp => sp.GetRequiredService<IDbContextFactory<AcmeManagerDbContext>>().CreateDbContext());
        hb.Services.AddAcmeManagerSecrets();
        // Apply registers acme.sh's account key with the CA.
        hb.Services.AddSingleton<IAcmeClient, CertesAcmeClient>();
        return hb.Build();
    }

    private static string? ArgValue(string[] args, string name)
    {
        var i = Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }
}