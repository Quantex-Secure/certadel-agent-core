using System.Runtime.Versioning;

using AcmeManager.Core.Plugins;

using Microsoft.Win32;

namespace AcmeManager.Service.Certificates;

/// <summary>
/// <see cref="ICertStoreCatalog"/> backed by the local machine's certificate
/// stores. Scans the registry's SystemCertificates keys (which list the physical
/// store names — My, WebHosting, Root, and any custom stores) and unions in the
/// well-known names so common choices are always present. Best-effort: returns a
/// sensible default list off Windows or if the registry can't be read.
/// </summary>
public sealed class WindowsCertStoreCatalog : ICertStoreCatalog
{
    // Always-offered names even if the registry scan finds nothing.
    private static readonly string[] WellKnown =
        ["My", "WebHosting", "Root", "CA", "TrustedPeople", "TrustedPublisher"];

    public IReadOnlyList<string> ListStoreNames() =>
        OperatingSystem.IsWindows() ? ListWindows() : WellKnown;

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<string> ListWindows()
    {
        var names = new HashSet<string>(WellKnown, StringComparer.OrdinalIgnoreCase);
        // LocalMachine stores first (what IIS/Schannel use), then CurrentUser.
        Scan(Registry.LocalMachine, names);
        Scan(Registry.CurrentUser, names);
        return names.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
    }

    [SupportedOSPlatform("windows")]
    private static void Scan(RegistryKey root, HashSet<string> names)
    {
        try
        {
            using var key = root.OpenSubKey(@"SOFTWARE\Microsoft\SystemCertificates");
            if (key is null)
            {
                return;
            }
            foreach (var name in key.GetSubKeyNames())
            {
                if (!string.IsNullOrWhiteSpace(name))
                {
                    names.Add(name);
                }
            }
        }
        catch
        {
            // No access / key missing — well-known names still cover the common cases.
        }
    }
}