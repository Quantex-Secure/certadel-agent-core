namespace AcmeManager.Api.Contracts;

/// <summary>
/// A reusable DNS provider profile on the agent: a validation plugin id plus its
/// canonical options blob (which references secrets by name only — no secret values).
/// The console snapshots one into a renewal's validation step, the same way the
/// agent's own New-Certificate page does.
/// </summary>
public sealed record DnsProviderDto(Guid Id, string Name, string PluginId, string OptionsJson);