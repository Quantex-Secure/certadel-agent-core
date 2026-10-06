namespace AcmeManager.Plugins.Linux.Synology;

/// <summary>Identity of the Synology DSM release the agent is running on.</summary>
public sealed record DsmInfo(string ProductVersion, string? BuildNumber);

/// <summary>
/// Detects Synology DSM. DSM is Linux underneath, but the agent runs there as an
/// unprivileged package user: no PAM, no root-only installers, and certificates
/// go into DSM through its Web API instead of files and service reloads.
/// </summary>
public static class DsmPlatform
{
    public const string VersionFile = "/etc.defaults/VERSION";

    private static readonly Lazy<DsmInfo?> CurrentInfo =
        new(() => OperatingSystem.IsLinux() ? Read(VersionFile) : null);

    /// <summary>The running DSM release, or null when this host is not DSM.</summary>
    public static DsmInfo? Current => CurrentInfo.Value;

    public static bool IsDsm => Current is not null;

    /// <summary>
    /// Parses DSM's shell-style VERSION file (<c>productversion="7.4.1"</c>).
    /// Returns null when the file is absent or is not a DSM version file.
    /// </summary>
    public static DsmInfo? Read(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            foreach (var parts in File.ReadLines(path).Select(line => line.Split('=', 2)).Where(p => p.Length == 2))
            {
                values.TryAdd(parts[0].Trim(), parts[1].Trim().Trim('"'));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        return values.TryGetValue("productversion", out var version) && version.Length > 0
            ? new DsmInfo(version, values.GetValueOrDefault("buildnumber"))
            : null;
    }
}
