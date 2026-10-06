using System.Text.Json;

using AcmeManager.Core.Plugins;
using AcmeManager.Core.Storage;
using AcmeManager.Core.Storage.Entities;
using AcmeManager.Plugins.Contracts.Storage;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AcmeManager.Core.Engine;

/// <summary>
/// Removes certificates from their configured stores and from the database.
/// Shared by renewal deletion (management API and the local UI) and by the
/// engine's post-renew pruning of superseded certificates. Store removal is
/// best-effort by design: a missing file or unavailable plugin is logged and
/// skipped — it must never block the database change or fail a renewal run.
/// </summary>
public sealed class CertificateCleanupService(
    AcmeManagerDbContext db,
    PluginCatalog catalog,
    IServiceProvider sp,
    ILogger<CertificateCleanupService> logger)
{
    /// <summary>
    /// Deletes a renewal outright: removes every issued certificate from its
    /// stores (best-effort), then deletes the row. Certificate rows cascade;
    /// history rows survive with a nulled renewal FK (audit trail).
    /// Returns false when the renewal doesn't exist.
    /// </summary>
    public async Task<bool> DeleteRenewalAsync(Guid renewalId, CancellationToken ct)
    {
        var renewal = await db.Renewals.FirstOrDefaultAsync(r => r.Id == renewalId, ct);
        if (renewal is null)
        {
            return false;
        }

        var certs = await db.Certificates.AsNoTracking()
            .Where(c => c.RenewalId == renewalId)
            .ToListAsync(ct);
        await DeleteFromStoresAsync(renewal.StoresJson, certs, keepReferences: new HashSet<(string, string)>(), ct);

        db.Renewals.Remove(renewal);
        await db.SaveChangesAsync(ct);

        logger.LogInformation(
            "Renewal '{Name}' ({Id}) deleted along with {Count} certificate record(s)",
            renewal.Name, renewalId, certs.Count);
        return true;
    }

    /// <summary>
    /// Prunes certificates superseded by a newly issued one: removes their
    /// store entries and database rows, keeping the certificate with
    /// <paramref name="keepThumbprint"/>. Store references the kept certificate
    /// still uses are never deleted — file stores overwrite in place, so the
    /// old row's path reference IS the new certificate's file.
    /// </summary>
    public async Task<int> RemoveSupersededAsync(Guid renewalId, string keepThumbprint, CancellationToken ct)
    {
        var renewal = await db.Renewals.AsNoTracking().FirstOrDefaultAsync(r => r.Id == renewalId, ct);
        if (renewal is null)
        {
            return 0;
        }

        var certs = await db.Certificates
            .Where(c => c.RenewalId == renewalId)
            .ToListAsync(ct);
        var kept = certs
            .Where(c => string.Equals(c.Thumbprint, keepThumbprint, StringComparison.OrdinalIgnoreCase))
            .ToList();
        var superseded = certs.Except(kept).ToList();
        if (superseded.Count == 0)
        {
            return 0;
        }

        var keepReferences = kept
            .SelectMany(c => ParseReferences(c.StoreReferencesJson))
            .ToHashSet();
        await DeleteFromStoresAsync(renewal.StoresJson, superseded, keepReferences, ct);

        db.Certificates.RemoveRange(superseded);
        await db.SaveChangesAsync(ct);
        return superseded.Count;
    }

    /// <summary>
    /// Removes what a run stored for a certificate that was never recorded (its
    /// verification failed and every installer rolled back). A reference that any
    /// recorded certificate of the renewal still lists is left alone: file stores
    /// overwrite in place, so that path is what the previous certificate is served from.
    /// </summary>
    public async Task RemoveUnrecordedAsync(Guid renewalId, IReadOnlyDictionary<string, string> storeReferences, CancellationToken ct)
    {
        var renewal = await db.Renewals.AsNoTracking().FirstOrDefaultAsync(r => r.Id == renewalId, ct);
        if (renewal is null || storeReferences.Count == 0)
        {
            return;
        }

        var recorded = await db.Certificates.AsNoTracking()
            .Where(c => c.RenewalId == renewalId)
            .ToListAsync(ct);
        var keepReferences = recorded
            .SelectMany(c => ParseReferences(c.StoreReferencesJson))
            .ToHashSet();

        var unrecorded = new Certificate { RenewalId = renewalId, StoreReferencesJson = JsonSerializer.Serialize(storeReferences) };
        await DeleteFromStoresAsync(renewal.StoresJson, [unrecorded], keepReferences, ct);
    }

    private async Task DeleteFromStoresAsync(
        string storesJson,
        IReadOnlyList<Certificate> certs,
        IReadOnlySet<(string PluginId, string Reference)> keepReferences,
        CancellationToken ct)
    {
        // Options per store plugin, from the renewal's configured store chain.
        var stepOptions = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var step in PluginStepSerializer.DeserializeList(storesJson))
        {
            stepOptions.TryAdd(step.PluginId, step.Options?.GetRawText());
        }

        var processed = new HashSet<(string PluginId, string Reference)>();
        foreach (var cert in certs)
        {
            foreach (var reference in ParseReferences(cert.StoreReferencesJson))
            {
                if (keepReferences.Contains(reference) || !processed.Add(reference))
                {
                    continue;
                }

                if (!stepOptions.TryGetValue(reference.PluginId, out var optionsJson))
                {
                    logger.LogWarning(
                        "Store '{PluginId}' is no longer configured on the renewal; leaving reference '{Reference}' in place",
                        reference.PluginId, reference.Reference);
                    continue;
                }

                var store = sp.GetKeyedService<IStore>(reference.PluginId);
                if (store is null)
                {
                    logger.LogWarning("Store plugin '{PluginId}' is not registered; skipping cleanup", reference.PluginId);
                    continue;
                }

                try
                {
                    var opts = catalog.DeserializeOptions(reference.PluginId, optionsJson);
                    await store.DeleteAsync(reference.Reference, new StoreContext(opts), ct);
                    logger.LogInformation(
                        "Removed certificate from store '{PluginId}' (reference '{Reference}')",
                        reference.PluginId, reference.Reference);
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex,
                        "Failed to remove reference '{Reference}' from store '{PluginId}'; continuing",
                        reference.Reference, reference.PluginId);
                }
            }
        }
    }

    private static IEnumerable<(string PluginId, string Reference)> ParseReferences(string? storeReferencesJson)
    {
        if (string.IsNullOrWhiteSpace(storeReferencesJson))
        {
            yield break;
        }

        Dictionary<string, string>? refs;
        try
        {
            refs = JsonSerializer.Deserialize<Dictionary<string, string>>(storeReferencesJson);
        }
        catch (JsonException)
        {
            yield break;
        }

        if (refs is null)
        {
            yield break;
        }

        foreach (var kv in refs)
        {
            yield return (kv.Key, kv.Value);
        }
    }
}