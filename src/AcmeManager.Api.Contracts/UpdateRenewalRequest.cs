namespace AcmeManager.Api.Contracts;

/// <summary>
/// Partial edit of a renewal from the console. Null members are left unchanged.
/// Plugin steps use the same wire JSON as <see cref="CreateRenewalRequest"/>
/// (a single <c>{"pluginId":"...","options":{...}}</c> object for Source/Validation,
/// an array of those for Stores/Installations). Secrets are referenced by name and
/// must already exist on the agent. <see cref="MaintenanceWindowJson"/>: null leaves
/// the window unchanged, an empty string clears it.
/// </summary>
public sealed record UpdateRenewalRequest(
    string? Name = null,
    int? RenewalWindowDays = null,
    bool? Enabled = null,
    Guid? AccountId = null,
    string? SourceJson = null,
    string? ValidationJson = null,
    string? StoresJson = null,
    string? InstallationsJson = null,
    string? MaintenanceWindowJson = null);