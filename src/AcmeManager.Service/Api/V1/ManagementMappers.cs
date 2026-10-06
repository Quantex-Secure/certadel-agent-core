using System.Text.Json;

using AcmeManager.Api.Contracts;
using AcmeManager.Core.Engine;
using AcmeManager.Core.Storage.Entities;

namespace AcmeManager.Service.Api.V1;

/// <summary>
/// Pure entity → wire-DTO mapping for the management API. Kept free of EF and
/// HTTP so it can be unit-tested directly. Status is computed via the shared
/// <see cref="CertificateStatusCalculator"/> so the agent and the console never
/// diverge on what "expiring soon" means.
/// </summary>
internal static class ManagementMappers
{
    public static CertificateSummaryDto ToCertificateSummary(
        Renewal renewal,
        Certificate? latest,
        DateTimeOffset now)
    {
        var status = CertificateStatusCalculator.Compute(
            renewal.Enabled, latest?.NotAfter, renewal.RenewalWindowDays, now, renewal.ConsecutiveFailures);

        return new CertificateSummaryDto(
            RenewalId: renewal.Id,
            Name: renewal.Name,
            Enabled: renewal.Enabled,
            AccountName: renewal.Account?.Name ?? renewal.AccountId.ToString(),
            Subject: latest?.Subject,
            Sans: ParseSans(latest?.SansJson),
            NotBefore: latest?.NotBefore,
            NotAfter: latest?.NotAfter,
            LastAttemptAt: renewal.LastAttemptAt,
            LastSuccessAt: renewal.LastSuccessAt,
            Status: status,
            LastRunStatus: DeriveLastRunStatus(renewal),
            Thumbprint: latest?.Thumbprint,
            ConsecutiveFailures: renewal.ConsecutiveFailures,
            Warning: renewal.LastRunWarning,
            Verified: latest?.Verified);
    }

    public static RenewalDetailDto ToRenewalDetail(
        Renewal renewal,
        Certificate? latest,
        IReadOnlyList<HistoryEntry> history,
        DateTimeOffset now)
    {
        return new RenewalDetailDto(
            Id: renewal.Id,
            Name: renewal.Name,
            Enabled: renewal.Enabled,
            AccountName: renewal.Account?.Name ?? renewal.AccountId.ToString(),
            RenewalWindowDays: renewal.RenewalWindowDays,
            SourcePluginId: PluginIdOf(renewal.SourceJson),
            ValidationPluginId: PluginIdOf(renewal.ValidationJson),
            StorePluginIds: PluginIdsOf(renewal.StoresJson),
            InstallationPluginIds: PluginIdsOf(renewal.InstallationsJson),
            LatestCertificate: latest is null ? null : ToCertificateSummary(renewal, latest, now),
            History: history.Select(ToHistoryEntry).ToList(),
            MaintenanceWindow: DescribeWindow(renewal.MaintenanceWindowJson));
    }

    public static HistoryEntryDto ToHistoryEntry(HistoryEntry h) =>
        new(h.At, h.Status.ToString(), h.Message, h.DurationMs);

    /// <summary>
    /// "Success" / "Warning" / "Failed" / null derived from the renewal's run
    /// facts: the engine sets <c>LastSuccessAt == LastAttemptAt</c> on success
    /// (with <c>LastRunWarning</c> when an installer bound nothing) and only
    /// bumps <c>LastAttemptAt</c> on failure.
    /// </summary>
    private static string? DeriveLastRunStatus(Renewal renewal)
    {
        if (renewal.LastAttemptAt is null)
        {
            return null;
        }
        if (renewal.LastSuccessAt != renewal.LastAttemptAt)
        {
            return "Failed";
        }
        return renewal.LastRunWarning is null ? "Success" : "Warning";
    }

    private static string? DescribeWindow(string? json)
    {
        try
        {
            return MaintenanceWindow.Parse(json)?.Describe();
        }
        catch (FormatException)
        {
            return "(invalid)";
        }
    }

    private static IReadOnlyList<string> ParseSans(string? sansJson)
    {
        if (string.IsNullOrWhiteSpace(sansJson))
        {
            return [];
        }
        try
        {
            return JsonSerializer.Deserialize<List<string>>(sansJson) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static string PluginIdOf(string json)
    {
        try
        {
            return PluginStepSerializer.DeserializeSingle(json).PluginId;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            return "";
        }
    }

    private static IReadOnlyList<string> PluginIdsOf(string json)
    {
        try
        {
            return PluginStepSerializer.DeserializeList(json).Select(s => s.PluginId).ToList();
        }
        catch (JsonException)
        {
            return [];
        }
    }
}