namespace AcmeManager.Core.Storage.Entities;

/// <summary>
/// A managed certificate definition. Plugin steps (source/validation/stores/
/// installations) are stored as JSON to keep the schema plugin-agnostic; the
/// engine deserializes through a plugin-id-aware type registry.
/// </summary>
public sealed class Renewal
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Name { get; set; } = "";

    public Guid AccountId { get; set; }

    public Account Account { get; set; } = null!;

    public string SourceJson { get; set; } = "";

    public string ValidationJson { get; set; } = "";

    public string StoresJson { get; set; } = "[]";

    public string InstallationsJson { get; set; } = "[]";

    public int RenewalWindowDays { get; set; } = 30;

    public bool Enabled { get; set; } = true;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? LastAttemptAt { get; set; }

    public DateTimeOffset? LastSuccessAt { get; set; }

    /// <summary>
    /// When set (UTC), the scheduler will not attempt this renewal until this time
    /// — used to honor a CA rate-limit "retry after". Cleared on the next success.
    /// </summary>
    public DateTimeOffset? RetryAfter { get; set; }

    /// <summary>
    /// Number of failed runs since the last success. Drives the scheduler's
    /// escalating retry back-off, the console's "Failing" status, and the
    /// failure alert threshold. Reset to 0 by a successful run.
    /// </summary>
    public int ConsecutiveFailures { get; set; }

    /// <summary>
    /// Set when the last successful run completed with a warning — typically an
    /// installer that ran but bound nothing, so the issued certificate is stored
    /// but not necessarily being served. Cleared by a clean success.
    /// </summary>
    public string? LastRunWarning { get; set; }

    /// <summary>
    /// Optional <see cref="Engine.MaintenanceWindow"/> as JSON. When set, the
    /// scheduler only starts this renewal inside the window; manual runs ignore it.
    /// </summary>
    public string? MaintenanceWindowJson { get; set; }
}