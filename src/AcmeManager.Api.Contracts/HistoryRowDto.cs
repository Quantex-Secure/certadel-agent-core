namespace AcmeManager.Api.Contracts;

/// <summary>One fleet-wide renewal-history row (across all renewals on an agent),
/// carrying the renewal name + id the per-renewal <see cref="HistoryEntryDto"/> omits.</summary>
public sealed record HistoryRowDto(
    Guid Id,
    Guid? RenewalId,
    string RenewalName,
    DateTimeOffset At,
    string Status,
    long DurationMs,
    string Message);