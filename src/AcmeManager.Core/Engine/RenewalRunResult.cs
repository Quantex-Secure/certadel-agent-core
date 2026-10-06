namespace AcmeManager.Core.Engine;

/// <param name="Warning">
/// Non-null when the run succeeded but an installer bound nothing (the cert is
/// issued and stored, yet the target may still serve the old one).
/// </param>
public sealed record RenewalRunResult(
    bool Success,
    DateTimeOffset? IssuedNotAfter,
    string? ErrorMessage,
    long DurationMs,
    string? Warning = null);