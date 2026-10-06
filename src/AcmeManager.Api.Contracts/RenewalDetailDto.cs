namespace AcmeManager.Api.Contracts;

/// <summary>
/// Full detail for a single renewal: its configuration (plugin ids only — never
/// secret-bearing options), the latest issued certificate, and recent run
/// history. Backs the console's per-certificate detail view.
/// </summary>
public sealed record RenewalDetailDto(
    Guid Id,
    string Name,
    bool Enabled,
    string AccountName,
    int RenewalWindowDays,
    string SourcePluginId,
    string ValidationPluginId,
    IReadOnlyList<string> StorePluginIds,
    IReadOnlyList<string> InstallationPluginIds,
    CertificateSummaryDto? LatestCertificate,
    IReadOnlyList<HistoryEntryDto> History,
    string? MaintenanceWindow = null);

/// <summary>
/// One renewal-attempt audit row (success or failure). <see cref="Status"/> is
/// the agent's history-status name (e.g. Success / Failed / Started / Skipped).
/// </summary>
public sealed record HistoryEntryDto(
    DateTimeOffset At,
    string Status,
    string Message,
    long DurationMs);