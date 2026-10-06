namespace AcmeManager.Plugins.Contracts.Notification;

public enum NotificationLevel
{
    Info,
    Warning,
    Error,
}

public interface INotifier : IPlugin
{
    ValueTask NotifyAsync(NotificationEvent evt, CancellationToken ct);
}

public sealed record NotificationEvent(
    string Subject,
    string Body,
    NotificationLevel Level,
    DateTimeOffset At);