namespace AcmeManager.Plugins.Contracts;

/// <summary>
/// Plugin API surface version. The host accepts plugins whose
/// <see cref="PluginAssemblyAttribute.HostApiVersion"/> matches its own
/// <see cref="PluginApi.Version"/>. Bump on breaking contract changes.
/// </summary>
public static class PluginApi
{
    public const string Version = "1.0";
}

/// <summary>
/// Stamped onto each plugin assembly so the host can validate compatibility
/// before loading. A missing or mismatched attribute is a hard reject — the
/// plugin is not loaded and an error is logged.
/// </summary>
[AttributeUsage(AttributeTargets.Assembly, AllowMultiple = false)]
public sealed class PluginAssemblyAttribute(string id, string version, string hostApiVersion) : Attribute
{
    public string Id { get; } = id;
    public string Version { get; } = version;
    public string HostApiVersion { get; } = hostApiVersion;
}