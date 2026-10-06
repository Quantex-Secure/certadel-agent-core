using System.Text.Json.Nodes;

using AcmeManager.Service.Migration.WinAcme; // MappedRenewal / ImportedSecret (shared import model)

namespace AcmeManager.Service.Migration.AcmeSh;

/// <summary>A chosen DNS provider profile to snapshot into a renewal's validation
/// (its plugin id + the canonical options blob, which already references its secret).</summary>
internal sealed record DnsProfileSnapshot(string PluginId, string OptionsJson);

/// <summary>
/// The operator's import choices (the import page's bottom section): which installer,
/// which store, and — per acme.sh DNS method in use — which configured DNS provider
/// profile to snapshot. The secret lives inside the profile, not here.
/// </summary>
internal sealed record AcmeShMapContext(
    string InstallerPluginId = "installer.haproxy",
    string HaProxyCertDir = "/etc/haproxy/certs",
    string ReloadCommand = "systemctl reload haproxy",
    string HaProxyGroup = "haproxy",
    string StorePluginId = "",
    string StorePath = "",
    DnsProfileSnapshot? DnsProfile = null);

/// <summary>
/// Translates an acme.sh renewal config into an acme-manager renewal: a manual
/// source (the domains), validation from the chosen DNS provider profile (or HTTP-01
/// for a webroot), and the selected installer/store. Anything without a chosen
/// profile falls back to manual DNS-01 with a review note.
/// </summary>
internal static class AcmeShMapper
{
    public static MappedRenewal Map(AcmeShRenewalConf conf, AcmeShMapContext context)
    {
        var notes = new List<string>();

        var identifiers = new JsonArray { conf.Domain };
        foreach (var alt in conf.AltNames)
        {
            identifiers.Add(alt);
        }
        var source = new JsonObject { ["identifiers"] = identifiers, ["commonName"] = conf.Domain };

        return new MappedRenewal(
            Name: conf.Domain,
            SourceJson: WireSingle("source.manual", source),
            ValidationJson: MapValidation(conf, context, notes),
            StoresJson: MapStore(conf, context),
            InstallationsJson: MapInstall(conf, context),
            Secrets: [],
            DnsProfile: null,
            Notes: notes);
    }

    private static string MapValidation(AcmeShRenewalConf conf, AcmeShMapContext context, List<string> notes)
    {
        var method = conf.ValidationMethod;

        // Filesystem webroot → HTTP-01 (no DNS provider needed).
        if (method.StartsWith('/'))
        {
            return WireSingle("validation.http-01.filesystem", new JsonObject { ["webRootPath"] = method });
        }

        // A DNS API → snapshot the selected provider profile verbatim (plugin + options,
        // including its secret reference). Configured once under DNS Providers.
        if (context.DnsProfile is { } profile && !string.IsNullOrEmpty(profile.PluginId))
        {
            notes.Add($"DNS via the '{profile.PluginId}' provider profile — verify its zone covers '{conf.Domain}'.");
            return WireRaw(profile.PluginId, profile.OptionsJson);
        }

        notes.Add($"acme.sh used '{method}' but no DNS provider was selected — imported as manual DNS-01. Pick one and re-import.");
        return WireSingle("validation.dns-01.manual", new JsonObject());
    }

    private static string MapInstall(AcmeShRenewalConf conf, AcmeShMapContext context)
    {
        if (context.InstallerPluginId == "installer.haproxy")
        {
            return WireList(("installer.haproxy", new JsonObject
            {
                ["pemPath"] = $"{context.HaProxyCertDir.TrimEnd('/')}/{conf.Domain}.pem",
                ["reloadCommand"] = context.ReloadCommand,
                ["group"] = context.HaProxyGroup,
            }));
        }
        return "[]"; // no installer selected
    }

    /// <summary>Default PEM-store directory. Deliberately NOT the HAProxy cert dir:
    /// HAProxy's <c>crt</c> loads every file there and a split cert-only file
    /// (<c>&lt;name&gt;-cert.pem</c>) breaks the whole reload.</summary>
    private const string DefaultPemStoreDir = "/var/lib/acme-manager/pem";

    private static string MapStore(AcmeShRenewalConf conf, AcmeShMapContext context)
    {
        if (context.StorePluginId != "store.pem")
        {
            return "[]";
        }
        var dir = string.IsNullOrWhiteSpace(context.StorePath)
            ? DefaultPemStoreDir
            : context.StorePath.TrimEnd('/');
        return WireList(("store.pem", new JsonObject { ["directoryPath"] = dir, ["baseName"] = conf.Domain }));
    }

    /// <summary>Best-effort registrable domain (last two labels) — used when pre-filling
    /// a DNS provider profile's zone.</summary>
    internal static string RegistrableDomain(string domain)
    {
        var labels = domain.Split('.', StringSplitOptions.RemoveEmptyEntries);
        return labels.Length <= 2 ? domain : string.Join('.', labels[^2..]);
    }

    private static string WireSingle(string pluginId, JsonObject options) =>
        new JsonObject { ["pluginId"] = pluginId, ["options"] = options }.ToJsonString();

    private static string WireRaw(string pluginId, string optionsJson)
    {
        JsonNode options;
        try
        {
            options = string.IsNullOrWhiteSpace(optionsJson) ? new JsonObject() : JsonNode.Parse(optionsJson) ?? new JsonObject();
        }
        catch
        {
            options = new JsonObject();
        }
        return new JsonObject { ["pluginId"] = pluginId, ["options"] = options }.ToJsonString();
    }

    private static string WireList(params (string PluginId, JsonObject Options)[] steps) =>
        new JsonArray(steps.Select(s =>
            (JsonNode)new JsonObject { ["pluginId"] = s.PluginId, ["options"] = s.Options }).ToArray()).ToJsonString();
}