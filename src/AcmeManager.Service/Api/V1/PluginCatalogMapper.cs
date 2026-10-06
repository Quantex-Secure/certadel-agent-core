using System.Collections;
using System.Reflection;
using System.Text;

using AcmeManager.Api.Contracts;
using AcmeManager.Core.Engine;
using AcmeManager.Core.Plugins;
using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Installation;
using AcmeManager.Plugins.Contracts.Sources;
using AcmeManager.Plugins.Contracts.Storage;
using AcmeManager.Plugins.Contracts.Validation;

using Microsoft.Extensions.DependencyInjection;

namespace AcmeManager.Service.Api.V1;

/// <summary>
/// Describes the plugin catalog as wire DTOs for remote clients. The option-field
/// reflection MUST mirror the agent web UI's <c>PluginOptionsForm</c> so the
/// console renders identical forms — same field-type mapping, same camelCase keys,
/// same SchemaVersion/EqualityContract exclusions.
/// </summary>
internal static class PluginCatalogMapper
{
    public static IReadOnlyList<PluginDescriptorDto> Describe(PluginCatalog catalog, IServiceProvider sp)
    {
        return catalog.All
            .OrderBy(r => r.Category)
            .ThenBy(r => r.Id, StringComparer.Ordinal)
            .Select(r =>
            {
                var meta = TryGetMetadata(r, sp);
                return new PluginDescriptorDto(
                    r.Id,
                    r.Category.ToString(),
                    meta?.Name ?? r.Id,
                    meta?.Description ?? "",
                    DescribeOptions(r.OptionsType));
            })
            .ToList();
    }

    private static PluginMetadata? TryGetMetadata(PluginRegistration reg, IServiceProvider sp)
    {
        try
        {
            object? plugin = reg.Category switch
            {
                PluginCategory.Source => sp.GetKeyedService<ISource>(reg.Id),
                PluginCategory.Validation => sp.GetKeyedService<IValidator>(reg.Id),
                PluginCategory.Store => sp.GetKeyedService<IStore>(reg.Id),
                PluginCategory.Installation => sp.GetKeyedService<IInstaller>(reg.Id),
                _ => null,
            };
            return (plugin as IPlugin)?.Metadata;
        }
        catch
        {
            return null;
        }
    }

    private static IReadOnlyList<PluginOptionFieldDto> DescribeOptions(Type optionsType) =>
        optionsType.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.CanRead && p.CanWrite
                && p.Name != nameof(PluginOptions.SchemaVersion) && p.Name != "EqualityContract")
            .OrderBy(p => p.Name, StringComparer.Ordinal)
            .Select(DescribeField)
            .ToList();

    private static PluginOptionFieldDto DescribeField(PropertyInfo prop)
    {
        var underlying = Nullable.GetUnderlyingType(prop.PropertyType) ?? prop.PropertyType;
        var isSecretRef = prop.GetCustomAttribute<SecretReferenceAttribute>() is not null && underlying == typeof(string);
        var isIisRef = prop.GetCustomAttribute<IisSiteReferenceAttribute>() is not null && underlying == typeof(string);
        var isCertStoreRef = prop.GetCustomAttribute<CertStoreReferenceAttribute>() is not null && underlying == typeof(string);

        var required = prop.GetCustomAttribute<RequiredOptionAttribute>() is not null;
        var nameLower = prop.Name.ToLowerInvariant();
        var sensitive = isSecretRef
            || nameLower.Contains("password", StringComparison.Ordinal)
            || nameLower.Contains("secret", StringComparison.Ordinal);

        string type;
        IReadOnlyList<string>? enumValues = null;
        if (isSecretRef)
        {
            type = PluginOptionFieldTypes.SecretRef;
        }
        else if (isIisRef)
        {
            type = PluginOptionFieldTypes.IisSiteRef;
        }
        else if (isCertStoreRef)
        {
            type = PluginOptionFieldTypes.CertStoreRef;
        }
        else if (underlying == typeof(bool))
        {
            type = PluginOptionFieldTypes.Bool;
        }
        else if (underlying.IsEnum)
        {
            type = PluginOptionFieldTypes.Enum;
            enumValues = Enum.GetNames(underlying);
        }
        else if (underlying == typeof(int) || underlying == typeof(long))
        {
            type = PluginOptionFieldTypes.Integer;
        }
        else if (underlying == typeof(TimeSpan))
        {
            type = PluginOptionFieldTypes.TimeSpan;
        }
        else if (underlying != typeof(string) && typeof(IEnumerable).IsAssignableFrom(underlying))
        {
            type = PluginOptionFieldTypes.StringList;
        }
        else
        {
            type = PluginOptionFieldTypes.Text;
        }

        var hidden = InlineSecrets.IsManagedSecretName(prop);
        return new PluginOptionFieldDto(ToCamelCase(prop.Name), ToDisplayLabel(prop.Name), type, sensitive, enumValues, required, hidden);
    }

    private static string ToCamelCase(string name) =>
        string.IsNullOrEmpty(name) || !char.IsUpper(name[0])
            ? name
            : char.ToLowerInvariant(name[0]) + name[1..];

    private static string ToDisplayLabel(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return name;
        }
        var sb = new StringBuilder(name.Length + 4);
        sb.Append(name[0]);
        for (var i = 1; i < name.Length; i++)
        {
            var c = name[i];
            var prev = name[i - 1];
            if (char.IsUpper(c) && (char.IsLower(prev) || (i + 1 < name.Length && char.IsLower(name[i + 1]))))
            {
                sb.Append(' ');
                sb.Append(char.ToLowerInvariant(c));
            }
            else
            {
                sb.Append(c);
            }
        }
        return sb.ToString();
    }
}