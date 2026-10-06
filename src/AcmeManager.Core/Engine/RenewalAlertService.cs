using AcmeManager.Core.Notifications;
using AcmeManager.Plugins.Contracts.Notification;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AcmeManager.Core.Engine;

/// <summary>
/// Turns a renewal's failure streak into something a human will notice. A
/// renewal that fails once is routine (a DNS hiccup, a CA blip); one that fails
/// <see cref="FailureThreshold"/> times in a row is an expiring certificate in
/// the making, so at that point — and at every multiple — this raises a
/// critical log line and fans the event out to every registered
/// <see cref="INotifier"/>. A recovery after such a streak is announced too.
/// Notification failures are logged, never propagated: alerting must not be
/// able to break the renewal that triggered it.
/// </summary>
public sealed class RenewalAlertService(
    IEnumerable<INotifier> notifiers,
    IOptions<NotificationOptions> options,
    ILogger<RenewalAlertService> logger)
{
    public int FailureThreshold => Math.Max(1, options.Value.FailureThreshold);

    /// <summary>True at the threshold and at every multiple of it.</summary>
    public static bool ShouldAlert(int consecutiveFailures, int threshold) =>
        threshold >= 1 && consecutiveFailures >= threshold && consecutiveFailures % threshold == 0;

    public bool ShouldAlert(int consecutiveFailures) => ShouldAlert(consecutiveFailures, FailureThreshold);

    public async Task OnFailureAsync(string renewalName, int consecutiveFailures, string error, CancellationToken ct)
    {
        if (!ShouldAlert(consecutiveFailures))
        {
            return;
        }

        logger.LogCritical(
            "Renewal '{Name}' has failed {Count} consecutive time(s). Last error: {Error}",
            renewalName, consecutiveFailures, error);

        await DispatchAsync(new NotificationEvent(
            Subject: $"[Certadel] Renewal '{renewalName}' failing ({consecutiveFailures} consecutive failures)",
            Body: $"Renewal '{renewalName}' on {Environment.MachineName} has failed {consecutiveFailures} times in a row and will keep retrying with back-off.\nLast error: {error}",
            Level: NotificationLevel.Error,
            At: DateTimeOffset.UtcNow), ct);
    }

    public async Task OnRecoveredAsync(string renewalName, int previousFailures, DateTimeOffset? notAfter, CancellationToken ct)
    {
        if (previousFailures < FailureThreshold)
        {
            return;
        }

        logger.LogInformation(
            "Renewal '{Name}' recovered after {Count} consecutive failure(s).", renewalName, previousFailures);

        await DispatchAsync(new NotificationEvent(
            Subject: $"[Certadel] Renewal '{renewalName}' recovered",
            Body: $"Renewal '{renewalName}' on {Environment.MachineName} succeeded after {previousFailures} consecutive failures."
                  + (notAfter is { } na ? $" New certificate expires {na:yyyy-MM-dd}." : string.Empty),
            Level: NotificationLevel.Info,
            At: DateTimeOffset.UtcNow), ct);
    }

    private async Task DispatchAsync(NotificationEvent evt, CancellationToken ct)
    {
        foreach (var notifier in notifiers)
        {
            try
            {
                await notifier.NotifyAsync(evt, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                // Includes a notifier's own timeout (TaskCanceledException with our
                // token still live): that's a delivery failure, not a cancellation.
                logger.LogError(ex, "Notifier '{Notifier}' failed to deliver '{Subject}'.", notifier.Metadata.Id, evt.Subject);
            }
        }
    }
}