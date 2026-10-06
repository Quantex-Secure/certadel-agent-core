namespace AcmeManager.Core.Plugins;

/// <summary>
/// Host capability that enumerates the Windows certificate store names present on
/// this machine (My, WebHosting, Root, and any custom stores), so the UI can offer
/// a store picker. Returns an empty list off Windows — callers fall back to a
/// free-text field.
/// </summary>
public interface ICertStoreCatalog
{
    IReadOnlyList<string> ListStoreNames();
}