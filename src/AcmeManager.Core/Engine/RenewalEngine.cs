using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

using AcmeManager.Core.Acme.Accounts;
using AcmeManager.Core.Acme.Orders;
using AcmeManager.Core.Plugins;
using AcmeManager.Core.Storage;
using AcmeManager.Core.Storage.Entities;
using AcmeManager.Core.Verification;
using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Installation;
using AcmeManager.Plugins.Contracts.Sources;
using AcmeManager.Plugins.Contracts.Storage;
using AcmeManager.Plugins.Contracts.Validation;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AcmeManager.Core.Engine;

/// <summary>
/// Runs one Renewal end-to-end: source → validation (via OrderRunner) →
/// stores → installers. Persists a <see cref="Certificate"/> row plus one
/// <see cref="HistoryEntry"/> per run (success, warning, or failure). Each step
/// resolves its plugin from keyed DI by the id stored in the Renewal row.
///
/// Outcome honesty: a run only counts as a clean success when every installer
/// reports it applied the certificate. An installer that bound nothing turns
/// the run into a <see cref="HistoryStatus.Warning"/> with the reason recorded
/// on the renewal, because "issued and stored" is not the same as "served".
/// After the installers, the engine probes every endpoint they reported and
/// only records success once the new certificate is observed in service; if it
/// isn't, each installer's rollback restores the previous certificate and the
/// run fails. Failures increment the renewal's consecutive-failure count (which
/// drives scheduler back-off and alerting) and are persisted on a cleared change
/// tracker, so a failed save can never commit the staged success state.
/// </summary>
public sealed class RenewalEngine(
    AcmeManagerDbContext db,
    PluginCatalog catalog,
    AccountService accounts,
    OrderRunner orderRunner,
    RenewalRunGuard runGuard,
    CertificateCleanupService cleanup,
    RenewalAlertService alerts,
    InstallVerificationRunner verification,
    IServiceProvider sp,
    ILogger<RenewalEngine> logger)
{
    public async Task<RenewalRunResult> RunAsync(Guid renewalId, CancellationToken ct)
    {
        // Single-flight: don't let a manual trigger and the scheduler (or two
        // clicks) run the same renewal at once and fight over one ACME order.
        if (!runGuard.TryBegin(renewalId))
        {
            logger.LogInformation("Renewal {Id} is already running; skipping this trigger.", renewalId);
            return new RenewalRunResult(false, null, "A run for this renewal is already in progress.", 0);
        }
        try
        {
            return await RunCoreAsync(renewalId, ct);
        }
        finally
        {
            runGuard.End(renewalId);
        }
    }

    private async Task<RenewalRunResult> RunCoreAsync(Guid renewalId, CancellationToken ct)
    {
        var (result, alert) = await RunAndPersistAsync(renewalId, ct);

        // Alerting happens after the outcome is decided and persisted, and can
        // never change it: a slow webhook must not turn a success into a failure.
        if (alert is not null)
        {
            try
            {
                await alert();
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                logger.LogError(ex, "Alert dispatch for renewal {Id} failed", renewalId);
            }
        }

        return result;
    }

    private async Task<(RenewalRunResult Result, Func<Task>? Alert)> RunAndPersistAsync(Guid renewalId, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var history = new HistoryEntry
        {
            RenewalId = renewalId,
            At = DateTimeOffset.UtcNow,
            Status = HistoryStatus.Started,
            Message = "Renewal started",
        };

        try
        {
            var renewal = await db.Renewals
                .Include(r => r.Account)
                .FirstOrDefaultAsync(r => r.Id == renewalId, ct)
                ?? throw new InvalidOperationException($"Renewal {renewalId} not found");

            var account = await accounts.LoadAsync(renewal.AccountId, ct)
                ?? throw new InvalidOperationException($"Account {renewal.AccountId} for renewal '{renewal.Name}' not found");

            logger.LogInformation("Renewal '{Name}' ({Id}) starting", renewal.Name, renewalId);

            var identifiers = await ResolveSourceAsync(renewal, ct);

            var (validator, validatorOptions) = await ResolveValidationStepAsync(renewal, ct);

            var orderResult = await orderRunner.RunAsync(
                account,
                identifiers,
                validator,
                opts: new OrderRunnerOptions
                {
                    ValidatorOptions = validatorOptions,
                    PollInterval = TimeSpan.FromSeconds(2),
                    MaxPolls = 30,
                    CertificateKeyAlgorithm = global::AcmeManager.Core.Acme.AcmeKeyAlgorithm.EcP256,
                },
                ct: ct);

            // Carry the renewal name so naming-capable stores (Windows cert store)
            // can stamp it as the cert's Friendly Name.
            var bundle = BuildBundle(orderResult) with { FriendlyName = renewal.Name };

            var storeRefs = await RunStoresAsync(renewal, bundle, ct);

            var installs = await RunInstallersAsync(renewal, bundle, storeRefs, ct);
            var warning = DescribeInstallWarning(installs);

            // Prove the certificate is in service before recording anything. A failed
            // check restores whatever each installer replaced and fails the run.
            var verdict = await verification.VerifyOrRollbackAsync(
                installs.Select(i => i.Result).ToList(), bundle.Thumbprint, ct);
            if (verdict.Kind == VerificationKind.FailedAndRolledBack)
            {
                if (verdict.AllRolledBack)
                {
                    // Nothing serves the new certificate: don't strand it in the stores.
                    try
                    {
                        await cleanup.RemoveUnrecordedAsync(renewalId, storeRefs, CancellationToken.None);
                    }
                    catch (Exception cleanupEx)
                    {
                        logger.LogWarning(cleanupEx, "Could not remove the unverified certificate from the stores; it may need manual cleanup");
                    }
                    throw new InvalidOperationException(
                        $"Post-install verification failed and the previous certificate was restored. {verdict.Detail}");
                }

                // Something may still be bound to the new certificate: leave every store
                // artefact in place and tell the operator exactly what to look at.
                logger.LogError("Post-install verification failed and NOT every installer could be rolled back; the stored certificate was left in place. {Detail}", verdict.Detail);
                throw new InvalidOperationException(
                    $"Post-install verification failed and rollback was incomplete — check the targets by hand. {verdict.Detail}");
            }
            bool? verified = verdict.Kind == VerificationKind.Verified ? true : null;
            if (verdict.Kind == VerificationKind.Unreachable)
            {
                var notVerified = $"not verified ({verdict.Detail})";
                warning = warning is null ? notVerified : $"{warning}; {notVerified}";
            }

            var previousFailures = renewal.ConsecutiveFailures;
            renewal.LastAttemptAt = DateTimeOffset.UtcNow;
            renewal.LastSuccessAt = renewal.LastAttemptAt;
            renewal.RetryAfter = null; // success clears any prior rate-limit pause
            renewal.ConsecutiveFailures = 0;
            renewal.LastRunWarning = warning;

            db.Certificates.Add(new Certificate
            {
                RenewalId = renewalId,
                Thumbprint = bundle.Thumbprint,
                Subject = "CN=" + bundle.CommonName,
                SansJson = JsonSerializer.Serialize(bundle.SubjectAlternativeNames),
                NotBefore = bundle.NotBefore,
                NotAfter = bundle.NotAfter,
                IssuedAt = DateTimeOffset.UtcNow,
                StoreReferencesJson = JsonSerializer.Serialize(storeRefs),
                Verified = verified,
                VerifiedAt = verified == true ? DateTimeOffset.UtcNow : null,
            });

            var stored = storeRefs.Count > 0 ? string.Join(", ", storeRefs.Keys) : "no store";
            history.Status = warning is null ? HistoryStatus.Success : HistoryStatus.Warning;
            var verifiedNote = verified == true ? $"; verified: {verdict.Detail}" : "";
            history.Message =
                $"Issued cert for {bundle.CommonName} (NotAfter {bundle.NotAfter:yyyy-MM-dd}); stored in {stored}; {DescribeInstalls(installs)}{verifiedNote}";
            history.DurationMs = sw.ElapsedMilliseconds;
            db.History.Add(history);

            await db.SaveChangesAsync(ct);

            if (warning is null)
            {
                logger.LogInformation(
                    "Renewal '{Name}' succeeded in {Ms}ms — NotAfter {NotAfter:O}",
                    renewal.Name, sw.ElapsedMilliseconds, bundle.NotAfter);
            }
            else
            {
                logger.LogWarning(
                    "Renewal '{Name}' issued a certificate (NotAfter {NotAfter:O}) but finished with a warning: {Warning}",
                    renewal.Name, bundle.NotAfter, warning);
            }

            // Prune the certificates this run superseded (store entries + DB rows).
            // Best-effort: the renewal already succeeded, so a cleanup failure is
            // logged but never turns the run into a failure.
            try
            {
                var pruned = await cleanup.RemoveSupersededAsync(renewalId, bundle.Thumbprint, ct);
                if (pruned > 0)
                {
                    logger.LogInformation(
                        "Pruned {Count} superseded certificate(s) for renewal '{Name}'", pruned, renewal.Name);
                }
            }
            catch (Exception cleanupEx)
            {
                logger.LogWarning(cleanupEx,
                    "Post-renew cleanup failed for renewal {Id}; the new certificate is unaffected", renewalId);
            }

            var name = renewal.Name;
            var notAfter = bundle.NotAfter;
            return (
                new RenewalRunResult(true, notAfter, null, sw.ElapsedMilliseconds, warning),
                () => alerts.OnRecoveredAsync(name, previousFailures, notAfter, ct));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Renewal {Id} failed after {Ms}ms", renewalId, sw.ElapsedMilliseconds);

            // Honor a CA rate-limit "retry after" by pausing the renewal until then,
            // instead of the scheduler re-hitting the limit every retry interval.
            var rateLimited = AcmeManager.Core.Acme.AcmeRateLimit.TryGetRetryAfter(ex, out var retryAfter);

            history.Status = HistoryStatus.Failed;
            history.Message = rateLimited
                ? $"Rate limited by Let's Encrypt — renewal paused until {retryAfter.ToLocalTime():yyyy-MM-dd HH:mm} (local time). {ex.Message}"
                : ex.Message;
            history.ExceptionJson = JsonSerializer.Serialize(new
            {
                type = ex.GetType().FullName,
                message = ex.Message,
                stack = ex.StackTrace,
            });
            history.DurationMs = sw.ElapsedMilliseconds;

            var consecutiveFailures = 0;
            string? renewalName = null;
            try
            {
                // Discard everything this run staged (the new Certificate row, the
                // LastSuccessAt bump, …). If the failure was the success-path save
                // itself, re-saving on the same tracker would commit that success
                // state alongside a Failed history entry.
                db.ChangeTracker.Clear();

                var renewal = await db.Renewals.FindAsync([renewalId], ct);
                if (renewal is not null)
                {
                    renewal.LastAttemptAt = DateTimeOffset.UtcNow;
                    renewal.ConsecutiveFailures += 1;
                    if (rateLimited)
                    {
                        renewal.RetryAfter = retryAfter;
                    }
                    consecutiveFailures = renewal.ConsecutiveFailures;
                    renewalName = renewal.Name;
                }
                db.History.Add(history);
                await db.SaveChangesAsync(ct);
            }
            catch (Exception saveEx)
            {
                logger.LogError(saveEx, "Failed to persist history entry for failed renewal {Id}", renewalId);
            }

            var error = ex.Message;
            Func<Task>? alert = renewalName is null
                ? null
                : () => alerts.OnFailureAsync(renewalName, consecutiveFailures, error, ct);
            return (new RenewalRunResult(false, null, error, sw.ElapsedMilliseconds), alert);
        }
    }

    private async Task<IReadOnlyList<string>> ResolveSourceAsync(Renewal renewal, CancellationToken ct)
    {
        var step = PluginStepSerializer.DeserializeSingle(renewal.SourceJson);
        try
        {
            var source = sp.GetRequiredKeyedService<ISource>(step.PluginId);
            await EnsureAvailableAsync(source, ct);
            var opts = catalog.DeserializeOptions(step.PluginId, step.Options?.GetRawText());
            var result = await source.ResolveAsync(new SourceContext(opts), ct);
            return result.Identifiers;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new InvalidOperationException($"Source step '{step.PluginId}' failed: {ex.Message}", ex);
        }
    }

    private async Task<(IValidator Validator, PluginOptions Options)> ResolveValidationStepAsync(
        Renewal renewal,
        CancellationToken ct)
    {
        var step = PluginStepSerializer.DeserializeSingle(renewal.ValidationJson);
        var validator = sp.GetRequiredKeyedService<IValidator>(step.PluginId);
        await EnsureAvailableAsync(validator, ct);
        var opts = catalog.DeserializeOptions(step.PluginId, step.Options?.GetRawText());
        return (validator, opts);
    }

    private async Task<Dictionary<string, string>> RunStoresAsync(Renewal renewal, CertificateBundle bundle, CancellationToken ct)
    {
        var refs = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var step in PluginStepSerializer.DeserializeList(renewal.StoresJson))
        {
            try
            {
                var store = sp.GetRequiredKeyedService<IStore>(step.PluginId);
                await EnsureAvailableAsync(store, ct);
                var opts = catalog.DeserializeOptions(step.PluginId, step.Options?.GetRawText());
                var result = await store.StoreAsync(bundle, new StoreContext(opts), ct);
                refs[step.PluginId] = result.Reference;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                throw new InvalidOperationException($"Store step '{step.PluginId}' failed: {ex.Message}", ex);
            }
        }
        return refs;
    }

    /// <summary>One installer step's outcome, keyed by plugin id.</summary>
    internal sealed record InstallOutcome(string PluginId, InstallResult Result);

    /// <summary>Runs each installer step and collects what each one reported.</summary>
    private async Task<IReadOnlyList<InstallOutcome>> RunInstallersAsync(
        Renewal renewal,
        CertificateBundle bundle,
        IReadOnlyDictionary<string, string> storeRefs,
        CancellationToken ct)
    {
        var outcomes = new List<InstallOutcome>();
        foreach (var step in PluginStepSerializer.DeserializeList(renewal.InstallationsJson))
        {
            try
            {
                var installer = sp.GetRequiredKeyedService<IInstaller>(step.PluginId);
                await EnsureAvailableAsync(installer, ct);
                var opts = catalog.DeserializeOptions(step.PluginId, step.Options?.GetRawText());
                var result = await installer.InstallAsync(bundle, new InstallContext(opts, storeRefs), ct);
                outcomes.Add(new InstallOutcome(step.PluginId, result));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                throw new InvalidOperationException($"Installation step '{step.PluginId}' failed: {ex.Message}", ex);
            }
        }
        return outcomes;
    }

    /// <summary>
    /// Null when every installer applied the certificate (or there were none);
    /// otherwise one line naming each installer that bound nothing and why.
    /// </summary>
    internal static string? DescribeInstallWarning(IReadOnlyList<InstallOutcome> installs)
    {
        var missed = installs.Where(i => !i.Result.Applied).ToList();
        if (missed.Count == 0)
        {
            return null;
        }
        return string.Join("; ", missed.Select(m =>
            $"{m.PluginId} bound nothing" + (m.Result.Detail is null ? "" : $" ({m.Result.Detail})")));
    }

    /// <summary>Human summary of the installer stage for the history row.</summary>
    internal static string DescribeInstalls(IReadOnlyList<InstallOutcome> installs)
    {
        if (installs.Count == 0)
        {
            return "NOT bound — no installer configured (cert stored only)";
        }

        var applied = installs.Where(i => i.Result.Applied).Select(i => i.PluginId).ToList();
        var parts = new List<string>();
        if (applied.Count > 0)
        {
            parts.Add($"installed via {string.Join(", ", applied)}");
        }
        if (DescribeInstallWarning(installs) is { } warning)
        {
            parts.Add($"WARNING: {warning} — the target may still serve its previous certificate");
        }
        return string.Join("; ", parts);
    }

    private static async Task EnsureAvailableAsync(IPlugin plugin, CancellationToken ct)
    {
        if (plugin is ICapability cap)
        {
            var result = await cap.CheckAsync(ct);
            if (!result.Available)
            {
                throw new InvalidOperationException(
                    $"Plugin '{plugin.Metadata.Id}' is unavailable: {result.Reason ?? "no reason given"}");
            }
        }
    }

    private static CertificateBundle BuildBundle(OrderResult order)
    {
        var collection = X509CertificateLoader.LoadPkcs12Collection(order.Pfx, password: null);
        try
        {
            var leaf = collection.FirstOrDefault(c => c.HasPrivateKey)
                ?? throw new InvalidOperationException("No certificate with a private key found in the PFX");

            var commonName = leaf.GetNameInfo(X509NameType.DnsName, forIssuer: false);
            if (string.IsNullOrEmpty(commonName))
            {
                commonName = order.Identifiers[0];
            }
            // The bundle carries only value data + the raw PFX bytes, so the loaded
            // certs (and their unmanaged key handles) can be disposed once read.
            return new CertificateBundle(
                CommonName: commonName,
                SubjectAlternativeNames: order.Identifiers,
                PfxBytes: order.Pfx,
                PfxPassword: string.Empty,
                NotBefore: leaf.NotBefore,
                NotAfter: leaf.NotAfter,
                Thumbprint: leaf.Thumbprint);
        }
        finally
        {
            foreach (var cert in collection)
            {
                cert.Dispose();
            }
        }
    }
}