using AcmeManager.Core.Storage;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AcmeManager.Service.Handoff;

/// <summary>
/// <c>AcmeManager.Service handoff [--apply] [--only d1,d2] [--wacs PATH]</c> — stops the
/// old tool (acme.sh / win-acme) from renewing certs acme-manager has taken over. Run on
/// the host. Dry run by default (prints the exact commands); <c>--apply</c> executes them.
/// The deregister leaves cert files + bindings intact — it only stops future renewals.
/// </summary>
internal static class HandoffCli
{
    public static async Task<int> RunAsync(string[] args)
    {
        var apply = args.Contains("--apply", StringComparer.OrdinalIgnoreCase);
        var wacs = ArgValue(args, "--wacs");
        var only = ArgValue(args, "--only")
            ?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        using var host = BuildHost();
        using var scope = host.Services.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<HandoffService>();

        var preview = await service.PreviewAsync(wacs, default);
        if (preview.Error is not null)
        {
            Console.Error.WriteLine(preview.Error);
            return 2;
        }

        Console.WriteLine($"== acme-manager: handoff from {preview.Tool} ==");
        if (preview.Candidates.Count == 0)
        {
            Console.WriteLine($"Nothing to do — no {preview.Tool} renewal overlaps a cert acme-manager has issued.");
            return 0;
        }

        Console.WriteLine(apply
            ? "Mode: APPLY (deregistering)\n"
            : "Mode: DRY RUN (no changes; re-run with --apply)\n");
        foreach (var c in preview.Candidates)
        {
            Console.WriteLine($"  • {c.Target}  (acme-manager: '{c.CoveredBy}')");
            Console.WriteLine($"      {c.DisplayCommand}");
        }
        Console.WriteLine();

        if (!apply)
        {
            Console.WriteLine($"{preview.Candidates.Count} renewal(s) would be deregistered from {preview.Tool}. Re-run with --apply.");
            return 0;
        }

        var result = await service.ApplyAsync(wacs, only, default);
        foreach (var (target, status) in result.Items)
        {
            Console.WriteLine($"  • {target} → {status}");
        }
        Console.WriteLine($"\nDeregistered: {result.Done}  Failed: {result.Failed}");
        return result.Failed > 0 ? 3 : 0;
    }

    private static IHost BuildHost()
    {
        var hb = Host.CreateApplicationBuilder();
        hb.Logging.ClearProviders();
        var databaseFile = hb.Configuration["Storage:DatabaseFile"] ?? DataPaths.DatabaseFile;
        hb.Services.AddDbContextFactory<AcmeManagerDbContext>(o => o.UseSqlite($"Data Source={databaseFile}"));
        hb.Services.AddScoped(sp => sp.GetRequiredService<IDbContextFactory<AcmeManagerDbContext>>().CreateDbContext());
        hb.Services.AddScoped<HandoffService>();
        return hb.Build();
    }

    private static string? ArgValue(string[] args, string name)
    {
        var i = Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }
}