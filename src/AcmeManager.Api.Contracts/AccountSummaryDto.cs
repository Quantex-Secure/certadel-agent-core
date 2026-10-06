namespace AcmeManager.Api.Contracts;

/// <summary>An ACME account on the agent, for picking one when creating/editing a
/// renewal from the console. Never carries key material.</summary>
public sealed record AccountSummaryDto(
    Guid Id,
    string Name,
    string DirectoryUrl,
    string ContactEmail);