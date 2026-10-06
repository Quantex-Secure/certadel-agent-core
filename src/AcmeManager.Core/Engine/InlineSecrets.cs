using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;

using AcmeManager.Core.Plugins;
using AcmeManager.Plugins.Contracts;

namespace AcmeManager.Core.Engine;

/// <summary>Thrown when an inline credential cannot be stored (e.g. no account to name it by).</summary>
public sealed class InlineSecretException(string message) : InvalidOperationException(message);

/// <summary>A credential pulled out of step JSON, to be written once the save is validated.</summary>
public sealed record PendingSecret(string Name, string Value);

/// <summary>Step JSON with its inline credentials removed, plus the secrets to write.</summary>
public sealed record ExtractedSecrets(string Json, IReadOnlyList<PendingSecret> Secrets)
{
    /// <summary>Writes the pending secrets. Call only after the save has been validated.</summary>
    public async Task CommitAsync(InlineSecrets.StoreSecret store, CancellationToken ct)
    {
        foreach (var secret in Secrets)
        {
            await store(secret.Name, secret.Value, ct);
        }
    }
}

/// <summary>
/// Moves <see cref="InlineSecretAttribute"/> option values out of step JSON and into
/// the encrypted secret store, leaving only the secret's name behind. Every save path
/// (agent console and management API) runs this, so the credential is never written
/// into the renewal, never shown, and never exported.
///
/// Two phases: <see cref="Extract"/> is pure — it strips the values and decides the
/// secret names — so the caller can validate the cleaned JSON first and only then
/// <see cref="ExtractedSecrets.CommitAsync"/>. A rejected save writes nothing.
///
/// Secrets are named per renewal (<c>&lt;prefix&gt;: &lt;account&gt; (&lt;renewal&gt;)</c>),
/// so saving one renewal can never change another's credential.
/// </summary>
public static class InlineSecrets
{
    private const int MaxNamePartLength = 100;

    /// <summary>Stores one secret (create or replace).</summary>
    public delegate Task StoreSecret(string name, string value, CancellationToken ct);

    /// <summary>
    /// Strips every inline-secret option from <paramref name="json"/> (one step or a
    /// list) and returns the secrets to write. A non-empty value is assigned a
    /// per-renewal secret name, which its sibling option is pointed at. A blank value
    /// keeps the sibling — restored from <paramref name="existingJson"/> (the stored
    /// steps, matched by position and plugin id) when the client didn't send it.
    /// Unknown plugins and malformed JSON pass through unchanged.
    /// </summary>
    /// <exception cref="InlineSecretException">A value was given but the secret
    /// cannot be named safely (missing or invalid account or renewal name).</exception>
    public static ExtractedSecrets Extract(PluginCatalog catalog, string json, string renewalName, string? existingJson = null)
    {
        if (Parse(json) is not { } root)
        {
            return new ExtractedSecrets(json, []);
        }

        var existingSteps = existingJson is null || Parse(existingJson) is not { } existingRoot
            ? []
            : EnumerateSteps(existingRoot).ToList();
        var pending = new List<PendingSecret>();
        var changed = false;
        var index = 0;
        foreach (var step in EnumerateSteps(root))
        {
            var position = index++;
            if (step["pluginId"]?.GetValue<string>() is not { } pluginId
                || step["options"] is not JsonObject options
                || !catalog.TryGet(pluginId, out var registration))
            {
                continue;
            }
            foreach (var (prop, attr) in InlineProperties(registration.OptionsType))
            {
                var value = TakeAll(options, prop.Name);
                if (value is null)
                {
                    continue; // option absent: nothing to strip, nothing to keep
                }
                changed = true;

                var siblingKey = FindPropertyName(options, attr.SecretNameProperty)
                    ?? JsonNamingPolicy.CamelCase.ConvertName(attr.SecretNameProperty);
                if (value.Length > 0)
                {
                    var secretName = SecretName(options, attr, renewalName);
                    pending.Add(new PendingSecret(secretName, value));
                    options[siblingKey] = secretName;
                }
                else if (string.IsNullOrEmpty(StringValue(options[siblingKey]))
                    && StoredSibling(existingSteps, position, pluginId, attr.SecretNameProperty) is { } kept)
                {
                    options[siblingKey] = kept;
                }
            }
        }
        return new ExtractedSecrets(changed ? root.ToJsonString(PluginCatalog.JsonOpts) : json, pending);
    }

    /// <summary>True for an option that an <see cref="InlineSecretAttribute"/> manages
    /// (the secret-name sibling), which forms therefore hide.</summary>
    public static bool IsManagedSecretName(PropertyInfo prop) =>
        prop.DeclaringType is { } type
        && InlineProperties(type).Any(x => x.Attribute.SecretNameProperty == prop.Name);

    /// <summary>Removes every case variant of <paramref name="clrName"/> (so a
    /// duplicate key can't survive as plaintext) and returns the value, preferring the
    /// camelCase key. Null when the option was absent.</summary>
    private static string? TakeAll(JsonObject options, string clrName)
    {
        var keys = options.Select(kv => kv.Key)
            .Where(k => string.Equals(k, clrName, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (keys.Count == 0)
        {
            return null;
        }
        var camel = JsonNamingPolicy.CamelCase.ConvertName(clrName);
        var preferred = keys.Contains(camel, StringComparer.Ordinal) ? camel : keys[0];
        var value = StringValue(options[preferred]) ?? "";
        foreach (var key in keys)
        {
            options.Remove(key);
        }
        return value;
    }

    private static string? StoredSibling(List<JsonObject> existingSteps, int position, string pluginId, string clrName)
    {
        List<JsonObject> candidates = position < existingSteps.Count && Is(existingSteps[position], pluginId)
            ? [existingSteps[position]]
            : existingSteps.Where(s => Is(s, pluginId)).ToList();
        if (candidates.Count != 1 || candidates[0]["options"] is not JsonObject options)
        {
            return null;
        }
        return FindPropertyName(options, clrName) is { } key && StringValue(options[key]) is { Length: > 0 } name
            ? name
            : null;
    }

    private static bool Is(JsonObject step, string pluginId) =>
        string.Equals(step["pluginId"]?.GetValue<string>(), pluginId, StringComparison.Ordinal);

    private static string SecretName(JsonObject options, InlineSecretAttribute attr, string renewalName)
    {
        var suffix = attr.NameSuffixProperty is { } suffixProp && FindPropertyName(options, suffixProp) is { } n
            ? StringValue(options[n])?.Trim()
            : null;
        if (attr.NameSuffixProperty is not null && string.IsNullOrEmpty(suffix))
        {
            throw new InlineSecretException(
                $"Enter the {JsonNamingPolicy.CamelCase.ConvertName(attr.NameSuffixProperty)} before the password.");
        }
        var renewal = renewalName.Trim();
        RequireSafe(suffix, "account");
        RequireSafe(renewal, "certificate name");
        if (renewal.Length == 0)
        {
            throw new InlineSecretException("The certificate needs a name before a password can be stored for it.");
        }
        return suffix is null ? $"{attr.NamePrefix} ({renewal})" : $"{attr.NamePrefix}: {suffix} ({renewal})";
    }

    private static void RequireSafe(string? part, string what)
    {
        if (part is not null && (part.Length > MaxNamePartLength || part.Any(char.IsControl)))
        {
            throw new InlineSecretException($"The {what} is too long or contains control characters.");
        }
    }

    private static IEnumerable<(PropertyInfo Property, InlineSecretAttribute Attribute)> InlineProperties(Type optionsType) =>
        optionsType.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.PropertyType == typeof(string))
            .Select(p => (p, p.GetCustomAttribute<InlineSecretAttribute>()))
            .Where(x => x.Item2 is not null)
            .Select(x => (x.p, x.Item2!));

    private static IEnumerable<JsonObject> EnumerateSteps(JsonNode root) => root switch
    {
        JsonArray list => list.OfType<JsonObject>(),
        JsonObject single => [single],
        _ => [],
    };

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

    private static string? StringValue(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue<string>(out var s) ? s : null;

    private static string? FindPropertyName(JsonObject options, string clrName) =>
        options.Select(kv => kv.Key).FirstOrDefault(k => string.Equals(k, clrName, StringComparison.OrdinalIgnoreCase));
}
