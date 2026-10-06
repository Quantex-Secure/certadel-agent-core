namespace AcmeManager.Api.Contracts;

/// <summary>
/// Outcome of a console-triggered "Renew now". Maps one-to-one onto the agent's
/// internal renewal-run result so the console can surface the same success /
/// failure / duration / new-expiry feedback the agent's own UI shows.
/// </summary>
/// <param name="Warning">Non-null when the run succeeded but an installer bound nothing.</param>
public sealed record RenewNowResultDto(
    bool Success,
    DateTimeOffset? IssuedNotAfter,
    string? ErrorMessage,
    long DurationMs,
    string? Warning = null);