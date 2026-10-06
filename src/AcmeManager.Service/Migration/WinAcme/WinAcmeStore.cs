using System.Text.Json;
using System.Text.Json.Nodes;

namespace AcmeManager.Service.Migration.WinAcme;

/// <summary>One win-acme renewal definition (the parsed <c>*.renewal.json</c>).</summary>
internal sealed record WinAcmeRenewal(string FilePath, JsonObject Root)
{
    public string Id => (Root["Id"]?.GetValue<string>()) ?? Path.GetFileName(FilePath);
    public string FriendlyName =>
        Root["LastFriendlyName"]?.GetValue<string>()
        ?? Root["Id"]?.GetValue<string>()
        ?? Path.GetFileNameWithoutExtension(FilePath);
}

/// <summary>
/// A per-CA win-acme folder: its account files (<c>Registration_v2</c> /
/// <c>Signer_v2</c>) and all renewals stored alongside them.
/// </summary>
internal sealed record WinAcmeCaFolder(
    string Path,
    JsonObject? Registration,
    string? SignerRaw,
    IReadOnlyList<WinAcmeRenewal> Renewals);

/// <summary>Everything discovered under a win-acme configuration directory.</summary>
internal sealed record WinAcmeConfig(string BaseDir, IReadOnlyList<WinAcmeCaFolder> CaFolders)
{
    public int RenewalCount => CaFolders.Sum(c => c.Renewals.Count);
}

internal static class WinAcmeStore
{
    private static readonly JsonNodeOptions NodeOpts = new() { PropertyNameCaseInsensitive = true };
    private static readonly JsonDocumentOptions DocOpts = new() { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip };

    /// <summary>Default win-acme configuration locations to probe when no path is given.</summary>
    public static IEnumerable<string> DefaultLocations()
    {
        var pd = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        yield return Path.Combine(pd, "win-acme");
        yield return Path.Combine(pd, "win-acme.v2");
        yield return Path.Combine(pd, "letsencrypt-win-simple"); // legacy name
    }

    /// <summary>Resolve the base dir to read: an explicit override, else the first default that exists.</summary>
    public static string? ResolveBaseDir(string? overridePath)
    {
        if (!string.IsNullOrWhiteSpace(overridePath))
        {
            return Directory.Exists(overridePath) ? overridePath : null;
        }
        return DefaultLocations().FirstOrDefault(Directory.Exists);
    }

    public static WinAcmeConfig Read(string baseDir)
    {
        // Renewals live in per-CA subfolders; scan recursively and group by folder.
        var renewalFiles = Directory.EnumerateFiles(baseDir, "*.renewal.json", SearchOption.AllDirectories);

        var folders = renewalFiles
            .GroupBy(f => Path.GetDirectoryName(f)!)
            .Select(g =>
            {
                var renewals = g
                    .Select(TryReadRenewal)
                    .Where(r => r is not null)
                    .Cast<WinAcmeRenewal>()
                    .OrderBy(r => r.FriendlyName, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                var registration = TryReadJsonObject(Path.Combine(g.Key, "Registration_v2"));
                var signerRaw = TryReadText(Path.Combine(g.Key, "Signer_v2"));

                return new WinAcmeCaFolder(g.Key, registration, signerRaw, renewals);
            })
            .Where(c => c.Renewals.Count > 0)
            .ToList();

        return new WinAcmeConfig(baseDir, folders);
    }

    private static WinAcmeRenewal? TryReadRenewal(string path)
    {
        try
        {
            var node = JsonNode.Parse(File.ReadAllText(path), NodeOpts, DocOpts);
            return node is JsonObject obj ? new WinAcmeRenewal(path, obj) : null;
        }
        catch
        {
            return null;
        }
    }

    private static JsonObject? TryReadJsonObject(string path)
    {
        if (!File.Exists(path)) return null;
        try { return JsonNode.Parse(File.ReadAllText(path), NodeOpts, DocOpts) as JsonObject; }
        catch { return null; }
    }

    private static string? TryReadText(string path) =>
        File.Exists(path) ? File.ReadAllText(path).Trim() : null;
}