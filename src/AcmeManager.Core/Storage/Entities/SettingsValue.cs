namespace AcmeManager.Core.Storage.Entities;

/// <summary>
/// Generic key/value app settings — schedule, log level, notification config,
/// auto-update channel, etc. Schema-less to keep small-knob settings flexible
/// without a migration per knob.
/// </summary>
public sealed class SettingsValue
{
    public string Key { get; set; } = "";

    public string Value { get; set; } = "";

    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}