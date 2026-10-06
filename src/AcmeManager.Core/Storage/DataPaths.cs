namespace AcmeManager.Core.Storage;

/// <summary>
/// Per-OS conventional data directory layout. Centralised here so plugins,
/// the host, and the migration tooling all agree on where state lives.
/// </summary>
public static class DataPaths
{
    /// <summary>
    /// Environment variable that relocates the whole data directory (database,
    /// secrets key, logs, endpoint certificates). Used by packagers that keep state
    /// elsewhere and by the test suite so it never touches a live installation.
    /// </summary>
    public const string RootOverrideVariable = "ACMEMANAGER_DATA_ROOT";

    private static readonly Lazy<string> RootValue = new(ResolveRoot);

    public static string Root => RootValue.Value;

    private static string ResolveRoot()
    {
        // A relative override would resolve against the service's working directory
        // (system32 for a Windows Service), so only an absolute path is honoured.
        var overridden = Environment.GetEnvironmentVariable(RootOverrideVariable);
        if (!string.IsNullOrWhiteSpace(overridden) && Path.IsPathRooted(overridden))
        {
            return Path.GetFullPath(overridden);
        }
        return OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AcmeManager")
            : "/var/lib/acme-manager";
    }

    public static string DatabaseFile => Path.Combine(Root, "acme-manager.db");

    public static string PluginsDir => Path.Combine(Root, "plugins");

    public static string LogsDir => Path.Combine(Root, "logs");

    public static string SecretsKeyFile => Path.Combine(Root, "secrets.key");
}