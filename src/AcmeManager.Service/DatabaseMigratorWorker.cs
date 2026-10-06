using AcmeManager.Core.Storage;

using Microsoft.EntityFrameworkCore;

namespace AcmeManager.Service;

/// <summary>
/// Applies EF Core migrations as the first registered hosted service.
///
/// This must NOT run top-level in Program.cs: everything before the host starts
/// executes before the process connects to the Windows Service Control Manager's
/// dispatcher, so it counts against the SCM's 30-second start timeout. On a slow
/// post-update reboot that killed the service with "did not respond to the start
/// or control request in a timely fashion". As a hosted service it runs after the
/// SCM has been told the service is running, and because it is registered before
/// the other workers (and the web server starts last), nothing touches the
/// database until the migration completes.
/// </summary>
public sealed class DatabaseMigratorWorker(
    IDbContextFactory<AcmeManagerDbContext> dbFactory,
    ILogger<DatabaseMigratorWorker> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        await db.Database.MigrateAsync(cancellationToken);

        // Write-ahead logging is persistent per database file. It lets the UI/API
        // read while the scheduler writes, so "database is locked" stops being a
        // routine event (and the renewal engine never has to persist a failure
        // record against a contended file).
        await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;", cancellationToken);
        logger.LogInformation("Database migrated (WAL): {Path}", db.Database.GetDbConnection().DataSource);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}