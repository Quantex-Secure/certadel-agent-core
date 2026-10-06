using System.Text.Json.Nodes;

namespace AcmeManager.Service.Migration.WinAcme;

/// <summary>A secret to create in acme-manager (plaintext; protected at apply time).</summary>
internal sealed record ImportedSecret(string Name, string Value);

/// <summary>A reusable DNS provider profile to create (deduped by the importer).</summary>
internal sealed record ImportedDnsProfile(string Name, string PluginId, JsonObject Options);

/// <summary>The acme-manager renewal an imported win-acme renewal maps to.</summary>
internal sealed record MappedRenewal(
    string Name,
    string SourceJson,
    string ValidationJson,
    string StoresJson,
    string InstallationsJson,
    IReadOnlyList<ImportedSecret> Secrets,
    ImportedDnsProfile? DnsProfile,
    IReadOnlyList<string> Notes);

/// <summary>
/// Machine context for an import, available when it runs on the IIS box (the
/// normal case). Lets the mapper produce runnable renewals instead of blanks.
/// </summary>
/// <param name="ResolveSiteName">win-acme site id → IIS site name.</param>
/// <param name="ResolveSiteHost">IIS site name → its primary binding hostname.</param>
/// <param name="AzureSecretName">The existing agent secret to reference for Azure DNS
/// validation. We never import win-acme's own client secret — the agent already owns
/// the service-principal secret created at setup; this points every imported Azure
/// renewal at it.</param>
/// <param name="CertStoreName">Override Windows store for every imported renewal
/// (e.g. "WebHosting"). Null/empty preserves win-acme's own store name.</param>
/// <param name="CertStoreLocation">Store location ("LocalMachine"/"CurrentUser");
/// defaults to LocalMachine.</param>
internal sealed record WinAcmeMapContext(
    Func<string, string?>? ResolveSiteName = null,
    Func<string, string?>? ResolveSiteHost = null,
    string? AzureSecretName = null,
    string? CertStoreName = null,
    string? CertStoreLocation = null);

/// <summary>
/// Translates a win-acme <c>*.renewal.json</c> into an acme-manager renewal.
/// Plugins are recognised by their option field-shape (more version-tolerant than
/// win-acme's plugin GUIDs). Anything that can't be mapped 1:1 is still imported
/// with a sensible default plus a review note, so every cert shows up on the
/// renewals page and nothing is silently dropped.
/// </summary>
internal static class WinAcmeMapper
{
    /// <param name="context">Machine context (site-id/host resolvers, the existing Azure
    /// secret to reference). When absent, IIS site/host fields are left blank with review
    /// notes and the Azure secret reference is left for the operator to set.</param>
    public static MappedRenewal Map(WinAcmeRenewal r, int index, WinAcmeMapContext? context = null)
    {
        context ??= new WinAcmeMapContext();
        var notes = new List<string>();
        var secrets = new List<ImportedSecret>();

        var (sourceId, sourceOpts, siteName, defaultHost) =
            MapSource(r.Root["TargetPluginOptions"] as JsonObject, r.FriendlyName, context, notes);
        var (valId, valOpts, dnsProfile) = MapValidation(r.Root["ValidationPluginOptions"] as JsonObject, context, notes);

        var stores = new List<(string, JsonObject)>();
        foreach (var node in AsArray(r.Root["StorePluginOptions"]))
        {
            if (node is JsonObject so && MapStore(so, context, notes) is { } m) stores.Add(m);
        }

        // The IIS installer must bind from the same Windows store the cert lands in.
        var certStoreName = stores
            .Where(s => s.Item1 == "store.winstore")
            .Select(s => s.Item2["storeName"]?.ToString())
            .FirstOrDefault(n => !string.IsNullOrEmpty(n)) ?? "My";

        var installs = new List<(string, JsonObject)>();
        foreach (var node in AsArray(r.Root["InstallationPluginOptions"]))
        {
            if (node is JsonObject io && MapInstall(io, siteName, defaultHost, certStoreName, context, notes) is { } m) installs.Add(m);
        }

        return new MappedRenewal(
            r.FriendlyName,
            WireSingle(sourceId, sourceOpts),
            WireSingle(valId, valOpts),
            WireList(stores),
            WireList(installs),
            secrets,
            dnsProfile,
            notes);
    }

    // ---------------- Source / target ----------------

    private static (string PluginId, JsonObject Options, string? SiteName, string? DefaultHost) MapSource(
        JsonObject? target, string friendlyName, WinAcmeMapContext context, List<string> notes)
    {
        if (target is null)
        {
            notes.Add("No target in renewal; imported as a manual source using the friendly name — verify the hostnames.");
            return ("source.manual",
                new JsonObject { ["identifiers"] = new JsonArray(friendlyName), ["commonName"] = friendlyName },
                null, friendlyName);
        }

        var names = StrArray(target, "AlternativeNames");
        var commonName = Str(target, "CommonName");
        var defaultHost = commonName ?? (names.Count > 0 ? names[0] : null);

        // IIS target: win-acme resolves hostnames from site bindings at runtime,
        // and stores the site by numeric ID. Resolve ID → name when we can (the
        // import runs on the IIS box) so the renewal is runnable as imported.
        var siteIds = StrArray(target, "IncludeSiteIds");
        if (siteIds.Count == 0 && Int(target, "SiteId") is { } sid) siteIds.Add(sid.ToString());

        string? siteName = null;
        if (siteIds.Count > 0 && context.ResolveSiteName is not null)
        {
            siteName = siteIds.Select(context.ResolveSiteName).FirstOrDefault(n => !string.IsNullOrEmpty(n));
            if (siteName is not null && siteIds.Count > 1)
            {
                notes.Add($"win-acme spanned IIS site ids [{string.Join(", ", siteIds)}]; acme-manager uses one site per renewal — imported against '{siteName}'. Split the others into their own renewals if needed.");
            }
        }

        // "(any host)" IIS renewals carry no hostname — win-acme reads it from the
        // site's bindings. Fill it from the live site so the installer Host isn't blank.
        if (defaultHost is null && siteName is not null && context.ResolveSiteHost is not null)
        {
            defaultHost = context.ResolveSiteHost(siteName);
        }

        if (names.Count > 0)
        {
            var ids = new JsonArray();
            foreach (var n in names) ids.Add(n);
            return ("source.manual",
                new JsonObject { ["identifiers"] = ids, ["commonName"] = commonName ?? names[0] },
                siteName, defaultHost);
        }

        if (siteIds.Count > 0)
        {
            if (siteName is not null)
            {
                return ("source.iis", new JsonObject { ["siteName"] = siteName }, siteName, defaultHost);
            }
            notes.Add($"IIS source: win-acme used site id(s) [{string.Join(", ", siteIds)}] and the name could not be resolved here. acme-manager binds IIS by site NAME — set the site name on this renewal after import.");
            return ("source.iis", new JsonObject { ["siteName"] = "" }, null, defaultHost);
        }

        notes.Add("Could not determine hostnames from the win-acme target — imported as manual using the friendly name; verify it.");
        return ("source.manual",
            new JsonObject { ["identifiers"] = new JsonArray(friendlyName), ["commonName"] = commonName ?? friendlyName },
            siteName, defaultHost ?? friendlyName);
    }

    // ---------------- Validation ----------------

    private static (string PluginId, JsonObject Options, ImportedDnsProfile? Profile) MapValidation(
        JsonObject? validation, WinAcmeMapContext context, List<string> notes)
    {
        if (validation is null)
        {
            notes.Add("No validation plugin in renewal — set one (e.g. DNS-01 Azure) after import.");
            return ("validation.dns-01.manual", new JsonObject(), null);
        }

        var isAzure = validation["SubscriptionId"] is not null
            || validation["TenantId"] is not null
            || validation["SecretSafe"] is not null
            || (Str(validation, "ResourceGroupName") is not null && Str(validation, "HostedZone") is not null);

        if (isAzure)
        {
            var clientId = Str(validation, "ClientId") ?? "";
            var useMsi = Bool(validation, "UseMsi");

            // We never carry win-acme's client secret over — the agent already owns
            // the Azure service-principal secret created at setup. Reference that
            // existing secret (chosen at import time); leave blank + note otherwise.
            var clientSecretSecretName = "";
            if (useMsi)
            {
                notes.Add("win-acme used Azure Managed Identity (UseMsi). Confirm acme-manager's Azure plugin is configured for MSI, or point the validation at a service-principal secret.");
            }
            else if (!string.IsNullOrEmpty(context.AzureSecretName))
            {
                clientSecretSecretName = context.AzureSecretName;
            }
            else
            {
                notes.Add("Azure validation: pick this renewal's client-secret on the import page (or set it in Settings → Secrets and point the validation at it). win-acme's stored secret is intentionally NOT imported.");
            }

            var opts = new JsonObject
            {
                ["tenantId"] = Str(validation, "TenantId") ?? "",
                ["clientId"] = clientId,
                ["subscriptionId"] = Str(validation, "SubscriptionId") ?? "",
                ["resourceGroupName"] = Str(validation, "ResourceGroupName") ?? "",
                ["zoneName"] = Str(validation, "HostedZone") ?? "",
                ["clientSecretSecretName"] = clientSecretSecretName,
                ["propagationDelay"] = "00:00:30",
                ["schemaVersion"] = 1,
            };

            return ("validation.dns-01.azure", opts, null);
        }

        // Anything else (HTTP-01, Cloudflare, etc.) — leave a placeholder + raw dump for review.
        notes.Add($"Validation plugin not auto-mapped. Original options: {validation.ToJsonString()}");
        return ("validation.dns-01.manual", new JsonObject(), null);
    }

    // Well-known win-acme plugin GUIDs. Default plugins are often serialized as just
    // {"Plugin": guid} with no fields, so GUID matching is more reliable than shape.
    private const string WaCertificateStore = "e30adc8e-d756-4e16-a6f2-450f784b1a97";
    private const string WaIisInstallation = "ea6a5be3-f8de-4d27-a6bd-750b619b2ee2";
    private const string WaNoneInstallation = "aecc502c-5f75-43d2-b578-f95d50c79ea1";

    // ---------------- Stores ----------------

    private static (string, JsonObject)? MapStore(JsonObject store, WinAcmeMapContext context, List<string> notes)
    {
        var plugin = Str(store, "Plugin");

        // Windows certificate store (win-acme CertificateStore). Use the store the
        // operator picked on the import page if any; else preserve win-acme's own
        // name — its IIS default is "WebHosting" (the central SSL store the bindings
        // reference), NOT "My"; forcing "My" would land the cert where nothing looks.
        if (string.Equals(plugin, WaCertificateStore, StringComparison.OrdinalIgnoreCase)
            || store["StoreName"] is not null || store["StoreLocation"] is not null)
        {
            var name = !string.IsNullOrEmpty(context.CertStoreName)
                ? context.CertStoreName
                : Str(store, "StoreName") ?? "My";
            var location = string.IsNullOrEmpty(context.CertStoreLocation) ? "LocalMachine" : context.CertStoreLocation;
            return ("store.winstore", new JsonObject { ["location"] = location, ["storeName"] = name });
        }

        var path = Str(store, "Path") ?? Str(store, "CertificatePath");
        if (path is not null)
        {
            // PfxFile vs PemFiles both carry a Path; disambiguate by password/marker fields.
            var looksPfx = store["PfxPassword"] is not null || path.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase);
            if (looksPfx)
            {
                var pw = WinAcmeProtectedString.Decode(Str(store, "PfxPassword"));
                return ("store.pfx", new JsonObject
                {
                    ["filePath"] = path,
                    ["password"] = pw.Kind == WinAcmeProtectedString.Kind.Plain ? pw.Value : "",
                });
            }
            notes.Add($"Store with path '{path}' assumed to be PEM files — verify after import.");
            return ("store.pem", new JsonObject { ["directoryPath"] = path });
        }

        if (store["Plugin"] is not null)
        {
            notes.Add($"Store plugin not auto-mapped: {store.ToJsonString()}");
        }
        return null;
    }

    // ---------------- Installation ----------------

    private static (string, JsonObject)? MapInstall(
        JsonObject install, string? siteName, string? defaultHost, string certStoreName, WinAcmeMapContext context, List<string> notes)
    {
        var plugin = Str(install, "Plugin");

        // "None" — a deliberate no-op installation; import as no installer (no warning).
        if (string.Equals(plugin, WaNoneInstallation, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        // IIS — often serialized as just {"Plugin": guid}; the site comes from the
        // target, unless the install step carries its own SiteId (which wins).
        if (string.Equals(plugin, WaIisInstallation, StringComparison.OrdinalIgnoreCase)
            || install["SiteId"] is not null || install["NewBindingPort"] is not null || install["NewBindingIp"] is not null)
        {
            var ownSiteId = Str(install, "SiteId");
            var resolvedSite = (ownSiteId is not null ? context.ResolveSiteName?.Invoke(ownSiteId) : null) ?? siteName;
            // Prefer the host the target gave us; else this install step's own site's binding.
            var host = defaultHost
                ?? (resolvedSite is not null ? context.ResolveSiteHost?.Invoke(resolvedSite) : null)
                ?? "";

            if (resolvedSite is null)
            {
                notes.Add(ownSiteId is not null
                    ? $"IIS install: win-acme used site id {ownSiteId} and the name could not be resolved here; set the acme-manager IIS site name on this renewal after import."
                    : "IIS install: set the acme-manager IIS site name on this renewal after import.");
            }
            if (host.Length == 0)
            {
                notes.Add("IIS install: win-acme carried no explicit hostname; the installer will bind the certificate's common name.");
            }

            return ("installer.iis", new JsonObject
            {
                ["siteName"] = resolvedSite ?? "",
                ["host"] = host,
                ["ip"] = Str(install, "NewBindingIp") ?? "*",
                ["port"] = Int(install, "NewBindingPort") ?? 443,
                ["certStoreReferenceKey"] = "store.winstore",
                ["certStoreName"] = certStoreName,
                ["requireSni"] = true,
            });
        }

        var script = Str(install, "Script");
        if (script is not null)
        {
            return ("installer.script", new JsonObject
            {
                ["scriptPath"] = script,
                ["arguments"] = Str(install, "ScriptParameters") ?? "",
                ["timeout"] = "00:02:00",
            });
        }

        if (install["Plugin"] is not null && Str(install, "Plugin") is { Length: > 0 })
        {
            // Manual/None install plugins are a no-op in acme-manager; only note real unknowns.
            notes.Add($"Installation plugin not auto-mapped: {install.ToJsonString()}");
        }
        return null;
    }

    // ---------------- wire + json helpers ----------------

    private static string WireSingle(string pluginId, JsonObject options) =>
        new JsonObject { ["pluginId"] = pluginId, ["options"] = options }.ToJsonString();

    private static string WireList(IEnumerable<(string PluginId, JsonObject Options)> steps) =>
        new JsonArray(steps.Select(s =>
            (JsonNode)new JsonObject { ["pluginId"] = s.PluginId, ["options"] = s.Options }).ToArray()).ToJsonString();

    private static IEnumerable<JsonNode?> AsArray(JsonNode? node) =>
        node is JsonArray a ? a : Enumerable.Empty<JsonNode?>();

    private static string? Str(JsonObject o, string name)
    {
        var n = o[name];
        if (n is null) return null;
        try { return n.GetValue<string>(); } catch { return n.ToString(); }
    }

    private static int? Int(JsonObject o, string name)
    {
        var n = o[name];
        if (n is null) return null;
        try { return n.GetValue<int>(); } catch { return int.TryParse(n.ToString(), out var v) ? v : null; }
    }

    private static bool Bool(JsonObject o, string name)
    {
        var n = o[name];
        if (n is null) return false;
        try { return n.GetValue<bool>(); } catch { return bool.TryParse(n.ToString(), out var v) && v; }
    }

    private static List<string> StrArray(JsonObject o, string name)
    {
        var result = new List<string>();
        if (o[name] is JsonArray a)
        {
            foreach (var e in a)
            {
                if (e is null) continue;
                try { result.Add(e.GetValue<string>()); } catch { result.Add(e.ToString()); }
            }
        }
        return result;
    }
}