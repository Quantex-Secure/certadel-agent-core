namespace AcmeManager.Api.Contracts;

/// <summary>
/// Creates a renewal remotely ("request a certificate" from the console).
/// Plugin steps use the same wire JSON the agent stores: a single
/// <c>{"pluginId":"...","options":{...}}</c> object for Source/Validation and
/// an array of those objects for Stores/Installations (null/empty ⇒ none).
/// Option values that reference secrets do so by name; the secrets must
/// already exist on the agent — this API never carries secret material.
/// </summary>
public sealed record CreateRenewalRequest(
    string Name,
    Guid AccountId,
    string SourceJson,
    string ValidationJson,
    string? StoresJson = null,
    string? InstallationsJson = null,
    int? RenewalWindowDays = null,
    bool? Enabled = null,
    string? MaintenanceWindowJson = null);