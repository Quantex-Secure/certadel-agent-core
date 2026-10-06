using AcmeManager.Plugins.Contracts.Installation;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AcmeManager.Core.Verification;

public enum VerificationKind
{
    /// <summary>Every endpoint the installers reported is serving the new certificate.</summary>
    Verified,

    /// <summary>Nothing was checked: no installer reported an endpoint, or verification was switched off.</summary>
    Skipped,

    /// <summary>
    /// No endpoint answered with a different certificate, but at least one could
    /// not be reached, so the install is recorded as unverified — never rolled
    /// back, because "can't connect" is not evidence the install went wrong.
    /// </summary>
    Unreachable,

    /// <summary>An endpoint answered with a different certificate (or the run was cancelled mid-check); every installer's rollback has been run.</summary>
    FailedAndRolledBack,
}

/// <param name="Detail">Human summary: per-endpoint verdicts, skip reasons, rollback notes.</param>
/// <param name="AllRolledBack">
/// For <see cref="VerificationKind.FailedAndRolledBack"/>: every applied step had a
/// rollback and it completed. When false, something may still be serving the new
/// certificate and nothing that backs it may be deleted.
/// </param>
public sealed record InstallVerification(VerificationKind Kind, string Detail, bool AllRolledBack = true);

/// <summary>
/// The step between "installers ran" and "renewal recorded". Collects the
/// endpoints every applied installer reported, asks the verifier whether they
/// serve the issued certificate, and on a definite mismatch runs each
/// installer's rollback in reverse order so the target returns to its previous
/// certificate. Rollback is attempted for every step even if one throws, and
/// runs to completion regardless of cancellation — a half-restored fleet is
/// worse than a slow shutdown. The whole check runs under a time budget; when it
/// runs out, whatever is still pending counts as unreachable, not as failed.
/// </summary>
public sealed class InstallVerificationRunner(
    IEndpointVerifier verifier,
    IOptions<TlsVerifierOptions> options,
    ILogger<InstallVerificationRunner> logger)
{
    public async Task<InstallVerification> VerifyOrRollbackAsync(
        IReadOnlyList<InstallResult> results,
        string expectedThumbprint,
        CancellationToken ct)
    {
        var endpoints = results
            .Where(r => r.Applied)
            .SelectMany(r => r.Endpoints)
            .Distinct()
            .ToList();
        var skipReasons = results
            .Where(r => !string.IsNullOrEmpty(r.VerificationSkippedReason))
            .Select(r => r.VerificationSkippedReason!)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (endpoints.Count == 0)
        {
            var reason = skipReasons.Count > 0
                ? string.Join("; ", skipReasons)
                : results.Any(r => r.Applied)
                    ? "the installer reported no endpoint to check"
                    : "nothing was installed";
            return new InstallVerification(VerificationKind.Skipped, reason);
        }

        VerificationResult outcome;
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(TimeSpan.FromSeconds(Math.Max(10, options.Value.BudgetSeconds)));
        try
        {
            outcome = await verifier.VerifyAsync(endpoints, expectedThumbprint, budget.Token);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // The run itself was cancelled (service stopping). Leaving a certificate
            // installed but unrecorded would strand it; restore the known state.
            logger.LogWarning("Verification cancelled; restoring the previous certificate.");
            var (notes, rolledBack) = await RollBackAsync(results);
            return new InstallVerification(VerificationKind.FailedAndRolledBack,
                "the run was cancelled during verification; " + string.Join("; ", notes), rolledBack);
        }
        catch (OperationCanceledException)
        {
            logger.LogWarning("Verification budget of {Seconds}s exhausted for {Count} endpoint(s); recording the install as unverified.",
                options.Value.BudgetSeconds, endpoints.Count);
            return new InstallVerification(VerificationKind.Unreachable,
                $"verification did not finish within {options.Value.BudgetSeconds}s for {string.Join(", ", endpoints)}");
        }

        var mismatches = outcome.Mismatches;
        if (mismatches.Count > 0)
        {
            logger.LogError("Post-install verification failed; restoring the previous certificate. {Summary}", outcome.Summary);
            var (notes, rolledBack) = await RollBackAsync(results);
            notes.Insert(0, outcome.Summary);
            return new InstallVerification(VerificationKind.FailedAndRolledBack, string.Join("; ", notes), rolledBack);
        }

        var unreachable = outcome.Unreachable;
        if (unreachable.Count > 0)
        {
            var detail = string.Join("; ", unreachable.Select(u => u.Describe()));
            logger.LogWarning("Could not verify the install: {Detail}", detail);
            return new InstallVerification(VerificationKind.Unreachable, detail);
        }

        var verifiedDetail = skipReasons.Count > 0
            ? $"{outcome.Summary} (not checked: {string.Join("; ", skipReasons)})"
            : outcome.Summary;
        return new InstallVerification(VerificationKind.Verified, verifiedDetail);
    }

    /// <summary>Runs every rollback in reverse order; returns notes and whether every applied step was restored.</summary>
    private async Task<(List<string> Notes, bool AllRolledBack)> RollBackAsync(IReadOnlyList<InstallResult> results)
    {
        var notes = new List<string>();
        var allRolledBack = true;
        foreach (var result in results.Where(r => r.Applied).Reverse())
        {
            var label = result.Detail ?? "installer";
            if (result.Rollback is null)
            {
                allRolledBack = false;
                notes.Add($"NO ROLLBACK available for {label} — it may still be serving the new certificate");
                continue;
            }
            try
            {
                await result.Rollback(CancellationToken.None);
                notes.Add($"rolled back {label}");
            }
            catch (Exception ex)
            {
                allRolledBack = false;
                logger.LogError(ex, "Rollback failed for {Step}", label);
                notes.Add($"ROLLBACK FAILED for {label}: {ex.Message}");
            }
        }
        return (notes, allRolledBack);
    }
}