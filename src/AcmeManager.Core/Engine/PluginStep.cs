using System.Text.Json;

using AcmeManager.Core.Plugins;
using AcmeManager.Plugins.Contracts;

namespace AcmeManager.Core.Engine;

/// <summary>
/// Wire format for a single plugin step stored in <c>Renewal.SourceJson</c>,
/// <c>ValidationJson</c>, and the array forms in <c>StoresJson</c> /
/// <c>InstallationsJson</c>:
/// <code>{ "pluginId": "...", "options": { ... } }</code>
/// </summary>
public sealed record PluginStepWire(string PluginId, JsonElement? Options);

public static class PluginStepSerializer
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static PluginStepWire DeserializeSingle(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new InvalidOperationException("Plugin step JSON is empty");
        }
        return JsonSerializer.Deserialize<PluginStepWire>(json, JsonOpts)
            ?? throw new InvalidOperationException("Plugin step JSON deserialized to null");
    }

    public static IReadOnlyList<PluginStepWire> DeserializeList(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }
        return JsonSerializer.Deserialize<List<PluginStepWire>>(json, JsonOpts) ?? [];
    }

    public static string SerializeSingle(string pluginId, PluginOptions options, PluginCatalog catalog)
    {
        var optsJson = catalog.SerializeOptions(options);
        using var doc = JsonDocument.Parse(optsJson);
        return JsonSerializer.Serialize(
            new PluginStepWire(pluginId, doc.RootElement.Clone()),
            JsonOpts);
    }

    /// <summary>Serialize already-built wire steps back to the stored array form.</summary>
    public static string SerializeWires(IEnumerable<PluginStepWire> wires) =>
        JsonSerializer.Serialize(wires.ToList(), JsonOpts);

    public static string SerializeList(IEnumerable<(string PluginId, PluginOptions Options)> steps, PluginCatalog catalog)
    {
        var wires = steps.Select(s =>
        {
            var optsJson = catalog.SerializeOptions(s.Options);
            using var doc = JsonDocument.Parse(optsJson);
            return new PluginStepWire(s.PluginId, doc.RootElement.Clone());
        }).ToList();
        return JsonSerializer.Serialize(wires, JsonOpts);
    }
}