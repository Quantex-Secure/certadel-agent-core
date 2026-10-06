namespace AcmeManager.Core.Engine;

/// <summary>
/// Everything the scheduler needs to know about one renewal to decide whether
/// to run it now. A plain value so the decision is a pure function.
/// </summary>
public sealed record RenewalScheduleFacts(
    bool Enabled,
    int RenewalWindowDays,
    DateTimeOffset? LastAttemptAt,
    DateTimeOffset? LastSuccessAt,
    DateTimeOffset? RetryAfter,
    int ConsecutiveFailures,
    DateTimeOffset? LatestNotBefore,
    DateTimeOffset? LatestNotAfter,
    MaintenanceWindow? Window = null);

/// <summary>The scheduler's verdict for one renewal, with a human-readable reason.</summary>
public sealed record DueDecision(bool IsDue, string Reason)
{
    public static DueDecision Due(string reason) => new(true, reason);

    public static DueDecision Skip(string reason) => new(false, reason);
}

/// <summary>
/// Pure "is this renewal due?" logic, extracted from the scheduler loop so it
/// can be unit-tested without a database or a clock:
/// <list type="number">
///   <item>Disabled renewals never run.</item>
///   <item>A CA rate-limit pause (<c>RetryAfter</c>) is honoured.</item>
///   <item>After a failure, retries back off exponentially from
///         <see cref="BaseRetryInterval"/> up to <see cref="MaxRetryInterval"/>.</item>
///   <item>After a success, the renewal is not re-run for at least
///         <see cref="MinSuccessInterval"/>, or a quarter of the issued
///         certificate's lifetime if that is longer — so a renewal window that is
///         wider than the certificate lifetime can never turn into an order every
///         tick until the CA rate-limits the domain.</item>
///   <item>Otherwise it is due when there is no certificate yet, or the latest
///         one expires inside the renewal window.</item>
///   <item>A due renewal with a maintenance window waits until the window is open.</item>
/// </list>
/// </summary>
public static class RenewalDueCalculator
{
    public static readonly TimeSpan BaseRetryInterval = TimeSpan.FromMinutes(15);

    public static readonly TimeSpan MaxRetryInterval = TimeSpan.FromHours(6);

    public static readonly TimeSpan MinSuccessInterval = TimeSpan.FromDays(1);

    /// <summary>
    /// A certificate this close to expiry renews even outside its maintenance
    /// window: a mis-set window must never be the reason a certificate lapses.
    /// </summary>
    public static readonly TimeSpan WindowOverrideBeforeExpiry = TimeSpan.FromDays(3);

    /// <summary>15 min, 30 min, 1 h, 2 h, 4 h, then 6 h for every failure after that.</summary>
    public static TimeSpan RetryInterval(int consecutiveFailures)
    {
        var exponent = Math.Clamp(consecutiveFailures - 1, 0, 10);
        var interval = TimeSpan.FromTicks(BaseRetryInterval.Ticks * (1L << exponent));
        return interval > MaxRetryInterval ? MaxRetryInterval : interval;
    }

    /// <summary>
    /// How long after a success the renewal is left alone: a quarter of the
    /// issued certificate's lifetime, and never less than <see cref="MinSuccessInterval"/>.
    /// </summary>
    public static TimeSpan SuccessFloor(DateTimeOffset? notBefore, DateTimeOffset? notAfter)
    {
        if (notBefore is { } from && notAfter is { } to && to > from)
        {
            var quarter = TimeSpan.FromTicks((to - from).Ticks / 4);
            return quarter > MinSuccessInterval ? quarter : MinSuccessInterval;
        }
        return MinSuccessInterval;
    }

    public static DueDecision Evaluate(RenewalScheduleFacts facts, DateTimeOffset now)
    {
        if (!facts.Enabled)
        {
            return DueDecision.Skip("disabled");
        }

        if (facts.RetryAfter is { } retryAfter && retryAfter > now)
        {
            return DueDecision.Skip($"paused by CA rate limit until {retryAfter:O}");
        }

        var lastRunFailed = facts.LastAttemptAt is not null && facts.LastSuccessAt != facts.LastAttemptAt;
        if (lastRunFailed)
        {
            var interval = RetryInterval(Math.Max(1, facts.ConsecutiveFailures));
            if (facts.LastAttemptAt > now - interval)
            {
                return DueDecision.Skip(
                    $"backing off after {Math.Max(1, facts.ConsecutiveFailures)} failure(s); next retry no sooner than {facts.LastAttemptAt.Value + interval:O}");
            }
        }

        if (facts.LastSuccessAt is { } lastSuccess)
        {
            var floor = SuccessFloor(facts.LatestNotBefore, facts.LatestNotAfter);
            if (lastSuccess > now - floor)
            {
                return DueDecision.Skip($"renewed {now - lastSuccess:g} ago; minimum interval after success is {floor:g}");
            }
        }

        if (facts.LatestNotAfter is null)
        {
            return WithinMaintenanceWindow(facts, now, "no certificate issued yet");
        }

        var threshold = now.AddDays(facts.RenewalWindowDays);
        if (facts.LatestNotAfter.Value > threshold)
        {
            return DueDecision.Skip($"expires {facts.LatestNotAfter.Value:O}, outside the {facts.RenewalWindowDays}-day window");
        }
        return WithinMaintenanceWindow(facts, now,
            $"expires {facts.LatestNotAfter.Value:O}, inside the {facts.RenewalWindowDays}-day window");
    }

    private static DueDecision WithinMaintenanceWindow(RenewalScheduleFacts facts, DateTimeOffset now, string dueReason)
    {
        if (facts.Window is { } window && !window.Contains(now))
        {
            if (facts.LatestNotAfter is { } notAfter && notAfter - now <= WindowOverrideBeforeExpiry)
            {
                return DueDecision.Due($"{dueReason}; the maintenance window {window.Describe()} is overridden because expiry is within {WindowOverrideBeforeExpiry.TotalDays:0} days");
            }
            return DueDecision.Skip($"{dueReason}, but outside the maintenance window {window.Describe()}");
        }
        return DueDecision.Due(dueReason);
    }
}