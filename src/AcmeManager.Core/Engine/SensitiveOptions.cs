using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;

using AcmeManager.Core.Plugins;
using AcmeManager.Plugins.Contracts;

namespace AcmeManager.Core.Engine;

/// <summary>Thrown when a redacted placeholder cannot be mapped back to a stored value.</summary>
public sealed class SensitiveOptionException(string message) : InvalidOperationException(message);

/// <summary>
/// Keeps credential-valued plugin options (<see cref="SensitiveOptionAttribute"/>)
/// off the wire. Works on the raw step JSON the renewal stores
/// (<c>{"pluginId":…,"options":{…}}</c> or a list of those) so the management
/// API can redact before returning and restore before persisting without the
/// console ever seeing the value.
/// </summary>
public static class SensitiveOptions
{
    /// <summary>
    /// Returns the step JSON with every sensitive, non-empty option value replaced
    /// by <see cref="SensitiveOptionAttribute.RedactedValue"/>. Unknown plugins and
    /// malformed JSON pass through unchanged.
    /// </summary>
    public static string Redact(PluginCatalog catalog, string json)
    {
        if (Parse(json) is not { } root)
        {
            return json;
        }

        var changed = false;
        foreach (var (_, options, _, name) in SensitiveSlots(catalog, root))
        {
            if (!string.IsNullOrEmpty(StringValue(options[name])))
            {
                options[name] = SensitiveOptionAttribute.RedactedValue;
                changed = true;
            }
        }
        return changed ? root.ToJsonString(PluginCatalog.JsonOpts) : json;
    }

    /// <summary>
    /// Returns <paramref name="incomingJson"/> with every redaction placeholder
    /// replaced by the value stored in <paramref name="existingJson"/> for the
    /// <em>same step</em>: matched by position when the plugin id at that position
    /// agrees, otherwise by plugin id when that id occurs exactly once in the
    /// stored config. A placeholder that cannot be mapped unambiguously — the step
    /// is new, the plugin changed, or the same plugin appears more than once —
    /// throws <see cref="SensitiveOptionException"/>: silently guessing would
    /// re-key one store's file with another store's password.
    /// </summary>
    public static string Restore(PluginCatalog catalog, string incomingJson, string existingJson)
    {
        if (Parse(incomingJson) is not { } root)
        {
            return incomingJson;
        }

        var existingSteps = Parse(existingJson) is { } existingRoot ? EnumerateSteps(existingRoot).ToList() : [];
        var incomingSteps = EnumerateSteps(root).ToList();
        var changed = false;

        for (var i = 0; i < incomingSteps.Count; i++)
        {
            var step = incomingSteps[i];
            if (step["pluginId"]?.GetValue<string>() is not { } pluginId
                || step["options"] is not JsonObject options
                || !catalog.TryGet(pluginId, out var registration))
            {
                continue;
            }

            foreach (var prop in SensitiveProperties(registration.OptionsType))
            {
                var name = FindPropertyName(options, prop.Name);
                if (name is null || StringValue(options[name]) != SensitiveOptionAttribute.RedactedValue)
                {
                    continue;
                }

                var source = MatchExistingStep(existingSteps, incomingSteps, i, pluginId)
                    ?? throw new SensitiveOptionException(
                        $"'{pluginId}.{prop.Name}' was sent redacted but no stored value corresponds to it (new or changed step). Supply the credential — preferably as a stored secret referenced by name.");
                var storedName = FindPropertyName(source, prop.Name);
                var stored = storedName is null ? null : StringValue(source[storedName]);
                if (string.IsNullOrEmpty(stored))
                {
                    throw new SensitiveOptionException(
                        $"'{pluginId}.{prop.Name}' was sent redacted but the stored configuration has no value for it.");
                }
                options[name] = stored;
                changed = true;
            }
        }

        return changed ? root.ToJsonString(PluginCatalog.JsonOpts) : incomingJson;
    }

    /// <summary>
    /// The first sensitive option set to a real value (non-empty and not the
    /// placeholder), as "pluginId.OptionName"; null when the config carries none.
    /// </summary>
    public static string? FindLiteral(PluginCatalog catalog, string json)
    {
        if (Parse(json) is not { } root)
        {
            return null;
        }
        foreach (var (pluginId, options, prop, name) in SensitiveSlots(catalog, root))
        {
            var value = StringValue(options[name]);
            if (!string.IsNullOrEmpty(value) && value != SensitiveOptionAttribute.RedactedValue)
            {
                return $"{pluginId}.{prop.Name}";
            }
        }
        return null;
    }

    /// <summary>
    /// The first sensitive option carrying the redaction placeholder, as
    /// "pluginId.OptionName"; null if none. A placeholder in a <em>create</em>
    /// request means a redacted config was copied from another agent — there is
    /// nothing to restore it from.
    /// </summary>
    public static string? FindPlaceholder(PluginCatalog catalog, string json)
    {
        if (Parse(json) is not { } root)
        {
            return null;
        }
        foreach (var (pluginId, options, prop, name) in SensitiveSlots(catalog, root))
        {
            if (StringValue(options[name]) == SensitiveOptionAttribute.RedactedValue)
            {
                return $"{pluginId}.{prop.Name}";
            }
        }
        return null;
    }

    private static JsonObject? MatchExistingStep(
        List<JsonObject> existingSteps, List<JsonObject> incomingSteps, int position, string pluginId)
    {
        if (position < existingSteps.Count
            && existingSteps[position]["pluginId"]?.GetValue<string>() == pluginId
            && existingSteps[position]["options"] is JsonObject atPosition)
        {
            return atPosition;
        }

        // Reordered list: fall back to plugin id only when it is unambiguous on
        // BOTH sides (exactly one such step stored and exactly one sent).
        static bool Is(JsonObject s, string id) => s["pluginId"]?.GetValue<string>() == id && s["options"] is JsonObject;
        var stored = existingSteps.Where(s => Is(s, pluginId)).ToList();
        var sent = incomingSteps.Count(s => Is(s, pluginId));
        return stored.Count == 1 && sent == 1 ? (JsonObject)stored[0]["options"]! : null;
    }

    private static IEnumerable<(string PluginId, JsonObject Options, PropertyInfo Property, string JsonName)> SensitiveSlots(
        PluginCatalog catalog, JsonNode root)
    {
        foreach (var step in EnumerateSteps(root))
        {
            if (step["pluginId"]?.GetValue<string>() is not { } pluginId
                || step["options"] is not JsonObject options
                || !catalog.TryGet(pluginId, out var registration))
            {
                continue;
            }
            foreach (var prop in SensitiveProperties(registration.OptionsType))
            {
                if (FindPropertyName(options, prop.Name) is { } name)
                {
                    yield return (pluginId, options, prop, name);
                }
            }
        }
    }

    private static JsonNode? Parse(string json)
    {
        try
        {
            return string.IsNullOrWhiteSpace(json) ? null : JsonNode.Parse(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static IEnumerable<JsonObject> EnumerateSteps(JsonNode root) => root switch
    {
        JsonArray list => list.OfType<JsonObject>(),
        JsonObject single => [single],
        _ => [],
    };

    private static string? StringValue(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue<string>(out var s) ? s : null;

    private static IEnumerable<PropertyInfo> SensitiveProperties(Type optionsType) =>
        optionsType
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.PropertyType == typeof(string) && p.GetCustomAttribute<SensitiveOptionAttribute>() is not null);

    /// <summary>The JSON property matching a CLR property name, whatever casing the writer used.</summary>
    private static string? FindPropertyName(JsonObject options, string clrName) =>
        options.Select(kv => kv.Key).FirstOrDefault(k => string.Equals(k, clrName, StringComparison.OrdinalIgnoreCase));
}