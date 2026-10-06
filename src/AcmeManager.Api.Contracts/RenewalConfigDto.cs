namespace AcmeManager.Api.Contracts;

/// <summary>
/// The full editable configuration of a renewal, including the raw plugin-step
/// option JSON — what an editor (the UCM) needs to pre-fill its forms. The plain
/// <see cref="RenewalDetailDto"/> deliberately omits option JSON; this endpoint
/// exposes it to the same authenticated, group-authorized, TLS-pinned operator the
/// web UI already shows it to. Option JSON references secrets by name, but a few
/// stores (e.g. PFX password) can carry an inline value — clients mask fields the
/// plugin schema marks <c>IsSecret</c>.
/// </summary>
public sealed record RenewalConfigDto(
    Guid Id,
    string Name,
    Guid AccountId,
    int RenewalWindowDays,
    bool Enabled,
    string SourceJson,
    string ValidationJson,
    string StoresJson,
    string InstallationsJson,
    string? MaintenanceWindowJson = null);