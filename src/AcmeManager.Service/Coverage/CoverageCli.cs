using AcmeManager.Core.Storage;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AcmeManager.Service.Coverage;

/// <summary>
/// <c>AcmeManager.Service coverage [--haproxy-config PATH]</c> — prints the
/// coverage report (what HAProxy serves vs what's renewing it). Read-only;
/// scriptable for monitoring/auditing across a fleet. Exit code 1 if any served
/// cert is unmanaged, so it can gate CI/monitoring.
/// </summary>
internal static class CoverageCli
{
    public static async Task<int> RunAsync(string[] args)
    {
        var configPath = ArgValue(args, "--haproxy-config");

        using var host = BuildHost();
        using var scope = host.Services.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<CoverageService>();

        var report = await service.ScanAsync(configPath, default);
        if (report.Error is not null)
        {
            Console.Error.WriteLine(report.Error);
            return 2;
        }

        Console.WriteLine("== acme-manager: coverage report ==");
        Console.WriteLine($"HAProxy cert sources: {string.Join(", ", report.CertSources)}");
        Console.WriteLine();
        foreach (var e in report.Entries.OrderByDescending(e => e.Status == CoverageStatus.Unmanaged))
        {
            var status = e.Status switch
            {
                CoverageStatus.Managed => "[ managed ]",
                CoverageStatus.OtherTool => "[ ext-tool ]",
                CoverageStatus.Unmanaged => "[UNMANAGED]",
                CoverageStatus.MissingCert => "[ MISSING! ]",
                _ => "[unreadable]",
            };
            var expiry = e.DaysUntilExpiry is { } d ? $"{d}d" : "?";
            Console.WriteLine($"  {status} {string.Join(", ", e.Domains),-40} {e.Issuer ?? "?",-16} expires {expiry,5}  — {e.Detail}");
        }
        Console.WriteLine();
        Console.WriteLine($"Served: {report.Total}  Managed: {report.Managed}  " +
            $"ext-tool: {report.OtherToolManaged}  UNMANAGED: {report.Unmanaged}  " +
            $"MISSING: {report.MissingCert}  Expiring≤21d: {report.ExpiringSoon}");

        return report.Unmanaged > 0 || report.MissingCert > 0 ? 1 : 0;
    }

    private static IHost BuildHost()
    {
        var hb = Host.CreateApplicationBuilder();
        hb.Logging.ClearProviders();
        var databaseFile = hb.Configuration["Storage:DatabaseFile"] ?? DataPaths.DatabaseFile;
        hb.Services.AddDbContextFactory<AcmeManagerDbContext>(o => o.UseSqlite($"Data Source={databaseFile}"));
        hb.Services.AddScoped(sp => sp.GetRequiredService<IDbContextFactory<AcmeManagerDbContext>>().CreateDbContext());
        hb.Services.AddScoped<CoverageService>();
        return hb.Build();
    }

    private static string? ArgValue(string[] args, string name)
    {
        var i = Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }
}