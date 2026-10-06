namespace AcmeManager.Core.Storage.Entities;

public enum HistoryStatus
{
    Started,
    Success,
    Failed,
    Skipped,

    /// <summary>
    /// The certificate was issued and stored, but at least one installer bound
    /// nothing — the target may still be serving the previous certificate.
    /// </summary>
    Warning,
}

/// <summary>
/// Audit log row for every renewal attempt — pass or fail. Drives the history
/// view in the UI and feeds notification plugins.
/// </summary>
public sealed class HistoryEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid? RenewalId { get; set; }

    public Renewal? Renewal { get; set; }

    public DateTimeOffset At { get; set; } = DateTimeOffset.UtcNow;

    public HistoryStatus Status { get; set; }

    public string Message { get; set; } = "";

    public long DurationMs { get; set; }

    public string? ExceptionJson { get; set; }
}