namespace AcmeManager.Api.Contracts;

/// <summary>
/// Describes a plugin and the schema of its options, so a remote client (the UCM
/// console) can render the same kind of option form the agent's web UI builds by
/// reflection — without having the plugin types loaded in its own process.
/// </summary>
public sealed record PluginDescriptorDto(
    string Id,
    string Category,
    string Name,
    string Description,
    IReadOnlyList<PluginOptionFieldDto> Options);

/// <summary>One configurable option field of a plugin.</summary>
/// <param name="Name">camelCase JSON key in the options object.</param>
/// <param name="Label">Human label.</param>
/// <param name="Type">One of <see cref="PluginOptionFieldTypes"/>.</param>
/// <param name="IsSecret">The value is sensitive (secret reference or a password/
/// secret field) — the client should mask it.</param>
/// <param name="EnumValues">Allowed values when <see cref="Type"/> is
/// <see cref="PluginOptionFieldTypes.Enum"/> (PascalCase names; sent camelCase).</param>
/// <param name="Hidden">Managed by the agent (e.g. the secret behind a write-only
/// password field): don't render it, but keep its value when editing.</param>
public sealed record PluginOptionFieldDto(
    string Name,
    string Label,
    string Type,
    bool IsSecret,
    IReadOnlyList<string>? EnumValues = null,
    bool Required = false,
    bool Hidden = false);

/// <summary>Field-type discriminators for <see cref="PluginOptionFieldDto.Type"/>.</summary>
public static class PluginOptionFieldTypes
{
    public const string Text = "text";
    public const string Bool = "bool";
    public const string Enum = "enum";
    public const string Integer = "integer";
    public const string TimeSpan = "timespan";
    public const string StringList = "stringList";
    public const string SecretRef = "secretRef";
    public const string IisSiteRef = "iisSiteRef";
    public const string CertStoreRef = "certStoreRef";
}