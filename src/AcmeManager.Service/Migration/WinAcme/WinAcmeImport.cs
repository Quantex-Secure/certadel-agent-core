using AcmeManager.Core.Security;
using AcmeManager.Core.Storage;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AcmeManager.Service.Migration.WinAcme;

/// <summary>
/// <c>AcmeManager.Service.exe import-winacme [--path DIR] [--apply] [--account NAME]</c>
///
/// Run this ON a server that has win-acme installed (so DPAPI-protected secrets
/// can be decrypted in place). The console front-end over
/// <see cref="WinAcmeImportService"/> — the same engine the web UI's import
/// page drives. Without <c>--apply</c> it prints a preview and changes nothing.
/// </summary>
internal static class WinAcmeImport
{
    public static async Task<int> RunAsync(string[] args)
    {
        var apply = args.Contains("--apply", StringComparer.OrdinalIgnoreCase);
        var noAccountImport = args.Contains("--no-account-import", StringComparer.OrdinalIgnoreCase);
        var path = ArgValue(args, "--path");
        var accountName = ArgValue(args, "--account");
        // Existing agent secret to reference for Azure DNS validation; win-acme's
        // own client secret is never imported.
        var azureSecret = ArgValue(args, "--azure-secret");
        // Override the Windows store for imported renewals (e.g. WebHosting); blank preserves win-acme's.
        var certStore = ArgValue(args, "--cert-store");
        var certStoreLocation = ArgValue(args, "--cert-store-location");
        // Selective import: --only name1,name2 (default: all).
        var only = ArgValue(args, "--only")
            ?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        Console.WriteLine("== acme-manager: import from win-acme ==");

        using var host = BuildHost();
        using var scope = host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();
        var protector = scope.ServiceProvider.GetRequiredService<ISecretProtector>();
        var service = new WinAcmeImportService(
            db, protector, scope.ServiceProvider.GetRequiredService<ILogger<WinAcmeImportService>>());

        var preview = service.Preview(path, azureSecret, certStore, certStoreLocation);
        if (preview.Error is not null)
        {
            Console.Error.WriteLine(preview.Error);
            Console.Error.WriteLine("Pass --path <win-acme config folder> (the one containing the per-CA subfolders).");
            return 2;
        }

        Console.WriteLine($"Source: {preview.BaseDir}");
        Console.WriteLine($"Found {preview.RenewalCount} renewal(s) across {preview.CaFolders.Count} CA folder(s).");
        Console.WriteLine(apply
            ? "Mode:   APPLY (writing to acme-manager)\n"
            : "Mode:   DRY RUN (no changes; re-run with --apply to import)\n");

        if (preview.RenewalCount == 0)
        {
            return 0;
        }

        foreach (var ca in preview.CaFolders)
        {
            Console.WriteLine($"--- CA folder: {ca.Path} ---");
            Console.WriteLine($"    win-acme account key: {ca.AccountKeyDescription}");
            Console.WriteLine($"    win-acme account URL : {ca.AccountUrl}");
            Console.WriteLine();
            foreach (var r in ca.Renewals)
            {
                PrintRenewal(r);
            }
        }

        var imported = 0;
        var skipped = 0;
        if (apply)
        {
            Directory.CreateDirectory(DataPaths.Root);
            await db.Database.MigrateAsync();
            Console.WriteLine();

            var result = await service.ApplyAsync(path, accountName, noAccountImport, default, azureSecret, certStore, certStoreLocation, only);
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
        Console.WriteLine($"Renewals seen:        {preview.RenewalCount}");
        Console.WriteLine($"With review notes:     {preview.WithNotes}");
        if (apply)
        {
            Console.WriteLine($"Imported:             {imported}");
            Console.WriteLine($"Skipped (existing):   {skipped}");
            Console.WriteLine("\nDone. Log in to acme-manager → Certificates to review (open one → Edit). Items with notes above need a quick check (DNS zone, IIS site/host).");
            if (!noAccountImport && accountName is null)
            {
                Console.WriteLine("Renewals run under your imported win-acme account (same key + registration).");
            }
        }
        else
        {
            Console.WriteLine("\nThis was a preview. Re-run with --apply to write these into acme-manager.");
        }
        return 0;
    }

    private static void PrintRenewal(WinAcmeRenewalPreview r)
    {
        Console.WriteLine($"  • {r.Name}");
        Console.WriteLine($"      source:        {r.SourcePluginId}");
        Console.WriteLine($"      validation:    {r.ValidationPluginId}");
        Console.WriteLine($"      stores:        {r.StorePluginIds}");
        Console.WriteLine($"      installations: {r.InstallationPluginIds}");
        if (r.SecretNames.Count > 0)
        {
            Console.WriteLine($"      secrets:       {string.Join(", ", r.SecretNames)}");
        }
        foreach (var n in r.Notes)
        {
            Console.WriteLine($"      ⚠ {n}");
        }
    }

    private static IHost BuildHost()
    {
        var hb = Host.CreateApplicationBuilder();
        hb.Logging.ClearProviders(); // CLI: our own Console.WriteLine is the output, suppress EF/host logs
        var databaseFile = hb.Configuration["Storage:DatabaseFile"] ?? DataPaths.DatabaseFile;
        Console.WriteLine($"Database: {databaseFile}");
        hb.Services.AddDbContextFactory<AcmeManagerDbContext>(o => o.UseSqlite($"Data Source={databaseFile}"));
        hb.Services.AddScoped(sp => sp.GetRequiredService<IDbContextFactory<AcmeManagerDbContext>>().CreateDbContext());
        hb.Services.AddAcmeManagerSecrets();
        return hb.Build();
    }

    private static string? ArgValue(string[] args, string name)
    {
        var i = Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }
}