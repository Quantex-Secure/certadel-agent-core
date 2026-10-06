using System.Runtime.Versioning;

using AcmeManager.Core.Plugins;

using Microsoft.Web.Administration;

namespace AcmeManager.Service.Iis;

/// <summary>
/// <see cref="IIisSiteCatalog"/> backed by the local IIS configuration
/// (Microsoft.Web.Administration). Best-effort: returns an empty list off Windows
/// or when IIS isn't installed/readable, so the UI degrades to a text field.
/// </summary>
public sealed class WindowsIisSiteCatalog : IIisSiteCatalog
{
    public IReadOnlyList<string> ListSiteNames() =>
        OperatingSystem.IsWindows() ? ListWindows() : [];

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<string> ListWindows()
    {
        try
        {
            using var serverManager = new ServerManager();
            return serverManager.Sites
                .Select(s => s.Name)
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch
        {
            // IIS not installed / no access — caller falls back to free-text.
            return [];
        }
    }
}