using AcmeManager.Core.Engine;
using AcmeManager.Core.Storage;

using Microsoft.EntityFrameworkCore;

namespace AcmeManager.Service;

/// <summary>
/// Background service that ticks every minute, asks <see cref="RenewalDueCalculator"/>
/// which enabled renewals are due, and invokes <see cref="RenewalEngine"/> on
/// each — sequentially, so concurrent renewals don't fight over challenge ports /
/// shared resources. The due decision (window, failure back-off, CA rate-limit
/// pause, post-success floor) lives in the calculator so it is unit-tested; this
/// class only gathers the facts and runs the engine.
/// </summary>
public sealed class RenewalSchedulerWorker(
    IServiceProvider services,
    ILogger<RenewalSchedulerWorker> logger) : BackgroundService
{
    private static readonly TimeSpan TickInterval = TimeSpan.FromMinutes(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation(
            "Renewal scheduler started — tick={Tick}, retry back-off {Min}..{Max}, post-success floor {Floor}",
            TickInterval, RenewalDueCalculator.BaseRetryInterval, RenewalDueCalculator.MaxRetryInterval,
            RenewalDueCalculator.MinSuccessInterval);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await TickAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Scheduler tick failed");
            }

            try
            {
                await Task.Delay(TickInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        logger.LogInformation("Renewal scheduler stopping");
    }

    private async Task TickAsync(CancellationToken ct)
    {
        var dueIds = await CollectDueRenewalsAsync(ct);
        if (dueIds.Count == 0)
        {
            return;
        }

        logger.LogInformation("{Count} renewal(s) due this tick", dueIds.Count);

        foreach (var id in dueIds)
        {
            if (ct.IsCancellationRequested) return;

            await using var scope = services.CreateAsyncScope();
            var engine = scope.ServiceProvider.GetRequiredService<RenewalEngine>();

            try
            {
                await engine.RunAsync(id, ct);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Renewal {Id} threw an unhandled exception", id);
            }
        }
    }

    private async Task<IReadOnlyList<Guid>> CollectDueRenewalsAsync(CancellationToken ct)
    {
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();

        var now = DateTimeOffset.UtcNow;
        var renewals = await db.Renewals.AsNoTracking()
            .Where(r => r.Enabled)
            .ToListAsync(ct);
        if (renewals.Count == 0)
        {
            return [];
        }

        // One query for every enabled renewal's certificates (not one per renewal
        // per tick). SQLite's EF provider can't aggregate DateTimeOffset, so the
        // latest-per-renewal reduction happens in memory.
        var ids = renewals.Select(r => r.Id).ToList();
        var certs = await db.Certificates.AsNoTracking()
            .Where(c => ids.Contains(c.RenewalId))
            .Select(c => new { c.RenewalId, c.NotBefore, c.NotAfter })
            .ToListAsync(ct);
        var latestByRenewal = certs
            .GroupBy(c => c.RenewalId)
            .ToDictionary(g => g.Key, g => g.OrderByDescending(c => c.NotAfter).First());

        var due = new List<Guid>();
        foreach (var r in renewals)
        {
            var latest = latestByRenewal.GetValueOrDefault(r.Id);
            MaintenanceWindow? window = null;
            try
            {
                window = MaintenanceWindow.Parse(r.MaintenanceWindowJson);
            }
            catch (FormatException ex)
            {
                logger.LogWarning("Renewal '{Name}' has an unusable maintenance window and will run without one: {Reason}", r.Name, ex.Message);
            }
            var facts = new RenewalScheduleFacts(
                Enabled: r.Enabled,
                RenewalWindowDays: r.RenewalWindowDays,
                LastAttemptAt: r.LastAttemptAt,
                LastSuccessAt: r.LastSuccessAt,
                RetryAfter: r.RetryAfter,
                ConsecutiveFailures: r.ConsecutiveFailures,
                LatestNotBefore: latest?.NotBefore,
                LatestNotAfter: latest?.NotAfter,
                Window: window);

            var decision = RenewalDueCalculator.Evaluate(facts, now);
            if (decision.IsDue)
            {
                logger.LogInformation("Renewal '{Name}' is due: {Reason}", r.Name, decision.Reason);
                due.Add(r.Id);
            }
            else
            {
                logger.LogDebug("Renewal '{Name}' skipped: {Reason}", r.Name, decision.Reason);
            }
        }
        return due;
    }
}