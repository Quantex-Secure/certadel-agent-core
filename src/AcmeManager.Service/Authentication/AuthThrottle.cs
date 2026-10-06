using System.Collections.Concurrent;

namespace AcmeManager.Service.Authentication;

/// <summary>
/// Per-account brute-force protection for the credential paths (Basic on the
/// management API, and the form login). The per-IP rate limiter is easily
/// sidestepped by rotating source addresses, and every attempt it lets through
/// costs a real OS logon — which on a domain member also advances the account's
/// lockout counter. This throttle keys on the <em>account</em> instead:
/// <list type="bullet">
///   <item>Attempts for one account are serialised (<see cref="EnterAsync"/>), so a
///         burst of parallel guesses can't all reach the OS before the first
///         failure is counted.</item>
///   <item>After <see cref="MaxFailures"/> failures inside <see cref="FailureWindow"/>
///         the account is locked for <see cref="InitialLockout"/>, doubling on each
///         further failure up to <see cref="MaxLockout"/>.</item>
///   <item>While locked, one attempt per <see cref="ProbeInterval"/> is still let
///         through, so the real operator with the right password gets in — an
///         attacker can slow an admin down, not shut them out.</item>
///   <item>A successful logon clears the record.</item>
/// </list>
/// </summary>
public sealed class AuthThrottle(TimeProvider? timeProvider = null)
{
    public static readonly TimeSpan FailureWindow = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan InitialLockout = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan MaxLockout = TimeSpan.FromHours(1);
    public static readonly TimeSpan ProbeInterval = TimeSpan.FromMinutes(1);
    public const int MaxFailures = 5;

    private const int PruneEvery = 256;

    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly ConcurrentDictionary<string, Record> _records = new(StringComparer.Ordinal);
    private int _addsSincePrune;

    private sealed class Record
    {
        public readonly SemaphoreSlim Gate = new(1, 1);
        public int Failures;
        public DateTimeOffset WindowStart;
        public DateTimeOffset LockedUntil;
        public DateTimeOffset LastProbe;
        public int Lockouts;
        public int InFlight;
    }

    /// <summary>
    /// Serialises attempts for one account: hold the returned lease around the
    /// lockout check, the OS logon and the outcome bookkeeping. Dispose to release.
    /// </summary>
    public async Task<IDisposable> EnterAsync(string username, CancellationToken ct)
    {
        var record = GetOrAddRecord(Normalize(username));
        Interlocked.Increment(ref record.InFlight);
        try
        {
            await record.Gate.WaitAsync(ct);
        }
        catch
        {
            Interlocked.Decrement(ref record.InFlight);
            throw;
        }
        return new Lease(record);
    }

    private sealed class Lease(Record record) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                record.Gate.Release();
                Interlocked.Decrement(ref record.InFlight);
            }
        }
    }

    /// <summary>
    /// True if the attempt for <paramref name="username"/> must be refused right
    /// now; <paramref name="retryAfter"/> says for how long. While an account is
    /// locked, one attempt per <see cref="ProbeInterval"/> is admitted anyway.
    /// </summary>
    public bool IsLockedOut(string username, out TimeSpan retryAfter)
    {
        var now = _time.GetUtcNow();
        if (_records.TryGetValue(Normalize(username), out var record))
        {
            lock (record)
            {
                if (record.LockedUntil > now)
                {
                    if (now - record.LastProbe >= ProbeInterval)
                    {
                        record.LastProbe = now; // admit this one as the periodic probe
                        retryAfter = TimeSpan.Zero;
                        return false;
                    }
                    retryAfter = record.LockedUntil - now;
                    return true;
                }
            }
        }
        retryAfter = TimeSpan.Zero;
        return false;
    }

    /// <summary>Records a failed attempt; returns the lockout it imposed, if any.</summary>
    public TimeSpan? RecordFailure(string username)
    {
        var now = _time.GetUtcNow();
        var record = GetOrAddRecord(Normalize(username));
        lock (record)
        {
            if (now - record.WindowStart > FailureWindow)
            {
                record.WindowStart = now;
                record.Failures = 0;
            }
            record.Failures++;

            if (record.Failures < MaxFailures && record.LockedUntil <= now)
            {
                return null;
            }

            // At the threshold (or failing while already locked): lock, escalating.
            var lockout = TimeSpan.FromTicks(InitialLockout.Ticks * (1L << Math.Min(record.Lockouts, 8)));
            if (lockout > MaxLockout)
            {
                lockout = MaxLockout;
            }
            record.Lockouts++;
            record.LockedUntil = now + lockout;
            record.LastProbe = now;
            record.Failures = 0;
            record.WindowStart = now;
            return lockout;
        }
    }

    /// <summary>Clears the account's failure history after a successful logon.</summary>
    public void RecordSuccess(string username)
    {
        if (_records.TryGetValue(Normalize(username), out var record))
        {
            lock (record)
            {
                record.Failures = 0;
                record.Lockouts = 0;
                record.LockedUntil = DateTimeOffset.MinValue;
                record.WindowStart = _time.GetUtcNow();
            }
        }
    }

    /// <summary>
    /// Drops records that are neither locked, nor inside a failure window, nor in
    /// use. Runs automatically every <see cref="PruneEvery"/> new accounts seen, so
    /// random usernames from an unauthenticated scanner can't grow the table
    /// without bound.
    /// </summary>
    public int Prune()
    {
        var now = _time.GetUtcNow();
        var removed = 0;
        foreach (var (key, record) in _records)
        {
            if (Volatile.Read(ref record.InFlight) > 0)
            {
                continue;
            }
            bool stale;
            lock (record)
            {
                stale = record.LockedUntil <= now && now - record.WindowStart > FailureWindow;
            }
            if (stale && _records.TryRemove(key, out _))
            {
                removed++;
            }
        }
        return removed;
    }

    private Record GetOrAddRecord(string key)
    {
        var added = false;
        var record = _records.GetOrAdd(key, _ =>
        {
            added = true;
            return new Record { WindowStart = _time.GetUtcNow() };
        });
        if (added && Interlocked.Increment(ref _addsSincePrune) >= PruneEvery)
        {
            Interlocked.Exchange(ref _addsSincePrune, 0);
            Prune();
        }
        return record;
    }

    /// <summary>
    /// One key per principal however it was spelled: <c>alice</c>,
    /// <c>DOMAIN\alice</c> and <c>alice@domain</c> all resolve to the same OS
    /// account, so they must share one failure budget.
    /// </summary>
    internal static string Normalize(string username)
    {
        var name = username.Trim();
        var backslash = name.LastIndexOf('\\');
        if (backslash >= 0)
        {
            name = name[(backslash + 1)..];
        }
        var at = name.IndexOf('@');
        if (at > 0)
        {
            name = name[..at];
        }
        return name.ToUpperInvariant();
    }
}