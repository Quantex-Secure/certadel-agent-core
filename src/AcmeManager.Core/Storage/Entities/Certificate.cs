namespace AcmeManager.Core.Storage.Entities;

/// <summary>
/// Metadata about a single issued certificate. The raw cert material lives in
/// configured stores (PEM file, Windows store, KeyVault, etc.); this row is
/// the index that lets the UI show "what do we have for renewal X".
/// </summary>
public sealed class Certificate
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid RenewalId { get; set; }

    public Renewal Renewal { get; set; } = null!;

    public string Thumbprint { get; set; } = "";

    public string Subject { get; set; } = "";

    public string SansJson { get; set; } = "[]";

    public DateTimeOffset NotBefore { get; set; }

    public DateTimeOffset NotAfter { get; set; }

    public DateTimeOffset IssuedAt { get; set; } = DateTimeOffset.UtcNow;

    public string? StoreReferencesJson { get; set; }

    /// <summary>
    /// True when the engine observed this certificate being served by every
    /// endpoint the installers reported; null when nothing could be checked
    /// (no installer, no endpoint, or verification switched off). Never false:
    /// a failed verification rolls the install back and no row is written.
    /// </summary>
    public bool? Verified { get; set; }

    public DateTimeOffset? VerifiedAt { get; set; }
}