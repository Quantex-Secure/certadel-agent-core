namespace AcmeManager.Api.Contracts;

/// <summary>One in-process log entry as exposed to the fleet console.</summary>
public sealed record LogEntryDto(
    DateTimeOffset At,
    string Level,
    string Message,
    string? Exception);