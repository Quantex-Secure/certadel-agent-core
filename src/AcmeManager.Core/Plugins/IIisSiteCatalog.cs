namespace AcmeManager.Core.Plugins;

/// <summary>
/// Host capability that enumerates the IIS site names present on this machine,
/// so the UI can offer a site picker for IIS source/installer plugins. Returns
/// an empty list when IIS (or Windows) is unavailable — callers fall back to a
/// free-text field in that case.
/// </summary>
public interface IIisSiteCatalog
{
    IReadOnlyList<string> ListSiteNames();
}