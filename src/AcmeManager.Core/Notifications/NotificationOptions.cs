namespace AcmeManager.Core.Notifications;

/// <summary>Bound from the <c>Notifications</c> configuration section.</summary>
public sealed class NotificationOptions
{
    public const string Section = "Notifications";

    /// <summary>
    /// Absolute http(s) URL that receives a JSON POST for every alert. Blank
    /// disables the webhook notifier. The body carries <c>subject</c>, <c>body</c>,
    /// <c>level</c>, <c>at</c>, plus <c>text</c> and <c>content</c> so Slack- and
    /// Discord-style incoming webhooks render it without a translation layer.
    /// </summary>
    public string? WebhookUrl { get; set; }

    /// <summary>
    /// Consecutive failures of one renewal before the first alert fires; alerts
    /// repeat at every multiple (3, 6, 9, …) so a renewal that keeps failing keeps
    /// making noise without paging on every 15-minute retry.
    /// </summary>
    public int FailureThreshold { get; set; } = 3;
}