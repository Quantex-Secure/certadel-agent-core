using System.Text;

namespace AcmeManager.Service.Migration.AcmeSh;

/// <summary>One acme.sh per-domain renewal config (<c>&lt;domain&gt;/&lt;domain&gt;.conf</c>),
/// parsed from its <c>Le_*</c> shell variables.</summary>
internal sealed record AcmeShRenewalConf(
    string Domain,
    IReadOnlyList<string> AltNames,
    string ValidationMethod,   // Le_Webroot: "dns_azure", "dns_cf", a webroot path, or "no"
    string DirectoryUrl,       // Le_API
    string KeyLength,          // Le_Keylength: "2048", "ec-256", ...
    string ReloadCommand,      // Le_ReloadCmd, base64-decoded
    string SourcePath);

/// <summary>Parses acme.sh's shell-style config files.</summary>
internal static class AcmeShConf
{
    public static AcmeShRenewalConf Parse(string confText, string sourcePath)
    {
        var vars = ParseVars(confText);
        var alt = vars.GetValueOrDefault("Le_Alt", "");
        var altNames = string.IsNullOrEmpty(alt) || alt.Equals("no", StringComparison.OrdinalIgnoreCase)
            ? []
            : alt.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        return new AcmeShRenewalConf(
            Domain: vars.GetValueOrDefault("Le_Domain", ""),
            AltNames: altNames,
            ValidationMethod: vars.GetValueOrDefault("Le_Webroot", ""),
            DirectoryUrl: vars.GetValueOrDefault("Le_API", ""),
            KeyLength: vars.GetValueOrDefault("Le_Keylength", ""),
            ReloadCommand: DecodeReload(vars.GetValueOrDefault("Le_ReloadCmd", "")),
            SourcePath: sourcePath);
    }

    /// <summary>Parses <c>KEY='value'</c> / <c>KEY="value"</c> lines into a map.</summary>
    internal static Dictionary<string, string> ParseVars(string text)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }
            var eq = line.IndexOf('=');
            if (eq <= 0)
            {
                continue;
            }
            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();
            if (value.Length >= 2 && (value[0] == '\'' || value[0] == '"') && value[^1] == value[0])
            {
                value = value[1..^1];
            }
            map[key] = value;
        }
        return map;
    }

    /// <summary>acme.sh wraps reload/hook commands as
    /// <c>__ACME_BASE64__START_&lt;base64&gt;__ACME_BASE64__END_</c>. Decode to the
    /// real command; pass anything else through unchanged.</summary>
    internal static string DecodeReload(string raw)
    {
        const string start = "__ACME_BASE64__START_";
        const string end = "__ACME_BASE64__END_";
        if (raw.StartsWith(start, StringComparison.Ordinal) && raw.EndsWith(end, StringComparison.Ordinal))
        {
            var b64 = raw[start.Length..^end.Length];
            try
            {
                return Encoding.UTF8.GetString(Convert.FromBase64String(b64)).Trim();
            }
            catch (FormatException)
            {
                return raw;
            }
        }
        return raw;
    }
}