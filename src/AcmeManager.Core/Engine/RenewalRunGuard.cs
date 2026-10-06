using System.Collections.Concurrent;

namespace AcmeManager.Core.Engine;

/// <summary>
/// Ensures a single renewal can't run concurrently with itself. A manual "Renew
/// now" / "use for this UI" click and the scheduler tick can otherwise fire the
/// same renewal at once, where they share one ACME order/authorization at the CA
/// and corrupt each other (e.g. "authorization must be pending"). Registered as a
/// singleton so the lock set is shared across all scopes.
/// </summary>
public sealed class RenewalRunGuard
{
    private readonly ConcurrentDictionary<Guid, SemaphoreSlim> _locks = new();

    /// <summary>Try to take the lock for a renewal without blocking. Returns false if a run is already in progress.</summary>
    public bool TryBegin(Guid renewalId) =>
        _locks.GetOrAdd(renewalId, _ => new SemaphoreSlim(1, 1)).Wait(0);

    /// <summary>Release the lock taken by a successful <see cref="TryBegin"/>.</summary>
    public void End(Guid renewalId)
    {
        if (_locks.TryGetValue(renewalId, out var sem))
        {
            sem.Release();
        }
    }
}