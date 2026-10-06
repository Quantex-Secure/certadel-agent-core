using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;

using AcmeManager.Plugins.Contracts;

namespace AcmeManager.Core.Plugins;

/// <summary>
/// Singleton lookup of registered plugins by id, plus typed JSON
/// (de)serialization for stored plugin options. Populated at startup by
/// <c>AddPluginCatalog(...)</c>; immutable thereafter.
/// </summary>
public sealed class PluginCatalog
{
    /// <summary>
    /// Shared options for stored plugin-options JSON. Enums are serialized as
    /// their names (not numeric indexes) so the UI's reflection-driven option
    /// forms can bind them via &lt;select&gt; without bespoke conversion.
    /// </summary>
    public static JsonSerializerOptions JsonOpts { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private readonly IReadOnlyDictionary<string, PluginRegistration> _byId;

    public PluginCatalog(IEnumerable<PluginRegistration> registrations)
    {
        _byId = registrations.ToDictionary(r => r.Id, StringComparer.Ordinal);
    }

    public IReadOnlyCollection<PluginRegistration> All => _byId.Values.ToList();

    public PluginRegistration Get(string id) =>
        _byId.TryGetValue(id, out var r)
            ? r
            : throw new KeyNotFoundException($"No plugin registered with id '{id}'");

    public bool TryGet(string id, [NotNullWhen(true)] out PluginRegistration? registration) =>
        _byId.TryGetValue(id, out registration);

    /// <summary>
    /// Deserializes a stored options JSON blob into the plugin's typed
    /// <see cref="PluginOptions"/> subclass. Empty/whitespace/<c>{}</c>/<c>null</c>
    /// resolve to the plugin's default options.
    /// </summary>
    public PluginOptions DeserializeOptions(string pluginId, string? json)
    {
        var reg = Get(pluginId);
        if (string.IsNullOrWhiteSpace(json) || json.Trim() is "{}" or "null")
        {
            return reg.DefaultOptionsFactory();
        }

        var obj = JsonSerializer.Deserialize(json, reg.OptionsType, JsonOpts);
        return (PluginOptions?)obj ?? reg.DefaultOptionsFactory();
    }

    public string SerializeOptions(PluginOptions options) =>
        JsonSerializer.Serialize(options, options.GetType(), JsonOpts);
}