using AcmeManager.Core.Engine;
using AcmeManager.Core.Notifications;
using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Notification;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AcmeManager.Tests.Unit;

public sealed class RenewalAlertServiceTests
{
    private sealed class RecordingNotifier(bool throwOnNotify = false) : INotifier
    {
        public List<NotificationEvent> Events { get; } = [];

        public PluginMetadata Metadata { get; } = new("notifier.test", "Test", "", PluginCategory.Notification, new Version(1, 0));

        public ValueTask NotifyAsync(NotificationEvent evt, CancellationToken ct)
        {
            if (throwOnNotify)
            {
                throw new InvalidOperationException("boom");
            }
            Events.Add(evt);
            return ValueTask.CompletedTask;
        }
    }

    private static RenewalAlertService Create(int threshold, params INotifier[] notifiers) =>
        new(notifiers, Options.Create(new NotificationOptions { FailureThreshold = threshold }), NullLogger<RenewalAlertService>.Instance);

    [Theory]
    [InlineData(1, 3, false)]
    [InlineData(2, 3, false)]
    [InlineData(3, 3, true)]
    [InlineData(4, 3, false)]
    [InlineData(6, 3, true)]
    [InlineData(1, 1, true)]
    [InlineData(2, 1, true)]
    [InlineData(3, 0, false)]
    public void ShouldAlert_AtThresholdAndEveryMultiple(int failures, int threshold, bool expected)
    {
        Assert.Equal(expected, RenewalAlertService.ShouldAlert(failures, threshold));
    }

    [Fact]
    public async Task OnFailure_BelowThreshold_IsSilent()
    {
        var notifier = new RecordingNotifier();
        var alerts = Create(threshold: 3, notifier);

        await alerts.OnFailureAsync("web", consecutiveFailures: 2, "dns timeout", default);

        Assert.Empty(notifier.Events);
    }

    [Fact]
    public async Task OnFailure_AtThreshold_NotifiesEveryNotifier_WithErrorLevel()
    {
        var first = new RecordingNotifier();
        var second = new RecordingNotifier();
        var alerts = Create(threshold: 3, first, second);

        await alerts.OnFailureAsync("web", consecutiveFailures: 3, "dns timeout", default);

        var evt = Assert.Single(first.Events);
        Assert.Single(second.Events);
        Assert.Equal(NotificationLevel.Error, evt.Level);
        Assert.Contains("web", evt.Subject);
        Assert.Contains("dns timeout", evt.Body);
    }

    [Fact]
    public async Task OnFailure_NotifierThrows_DoesNotPropagate_AndOthersStillRun()
    {
        var broken = new RecordingNotifier(throwOnNotify: true);
        var healthy = new RecordingNotifier();
        var alerts = Create(threshold: 1, broken, healthy);

        await alerts.OnFailureAsync("web", consecutiveFailures: 1, "x", default);

        Assert.Single(healthy.Events);
    }

    [Fact]
    public async Task OnRecovered_OnlyAfterAnAlertedStreak()
    {
        var notifier = new RecordingNotifier();
        var alerts = Create(threshold: 3, notifier);

        await alerts.OnRecoveredAsync("web", previousFailures: 2, notAfter: null, default);
        Assert.Empty(notifier.Events);

        await alerts.OnRecoveredAsync("web", previousFailures: 3, notAfter: DateTimeOffset.UtcNow.AddDays(90), default);
        var evt = Assert.Single(notifier.Events);
        Assert.Equal(NotificationLevel.Info, evt.Level);
        Assert.Contains("recovered", evt.Subject);
    }

    [Fact]
    public void ThresholdBelowOne_IsTreatedAsOne()
    {
        var alerts = Create(threshold: 0);
        Assert.Equal(1, alerts.FailureThreshold);
    }
}