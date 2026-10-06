namespace AcmeManager.Core.Storage.Entities;

/// <summary>
/// A reusable DNS provider profile — name + plugin id + options blob. Created
/// once under Settings, referenced from the New Renewal wizard. The wizard
/// snapshots the profile's plugin + options into <c>Renewal.ValidationJson</c>
/// at create time; subsequent edits to the profile do not retroactively
/// change existing renewals (secrets remain by-reference via name, so token
/// rotations still propagate).
/// </summary>
public sealed class DnsProvider
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Name { get; set; } = "";

    /// <summary>Validator plugin id, e.g. <c>validation.dns-01.cloudflare</c>.</summary>
    public string PluginId { get; set; } = "";

    public string OptionsJson { get; set; } = "{}";

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}