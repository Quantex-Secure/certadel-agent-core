using System.Diagnostics;
using System.Globalization;
using System.Text;

using AcmeManager.Api.Contracts;

namespace AcmeManager.Service.Coverage;

/// <summary>
/// Lists certificates issued by an Active Directory Certificate Services CA, so
/// the console's estate view can include the internal PKI's output alongside
/// public certificates. Uses <c>certutil -view</c> against the CA named in
/// <c>Coverage:AdcsCaConfig</c> (<c>host\CA name</c>); the service account needs
/// read access to the CA database. Not configured = empty list, never an error.
/// </summary>
public sealed class AdcsIssuedCertReader(IConfiguration configuration, ILogger<AdcsIssuedCertReader> logger)
{
    public const string ConfigKey = "Coverage:AdcsCaConfig";

    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(2);

    /// <summary>Columns requested from the CA database, in this order.</summary>
    internal const string Columns = "SerialNumber,CertificateHash,NotBefore,NotAfter,CommonName,CertificateTemplate,RequesterName";

    public string? CaConfig => configuration[ConfigKey];

    public bool IsConfigured => !string.IsNullOrWhiteSpace(CaConfig);

    public async Task<IReadOnlyList<AdcsCertificateDto>> ReadAsync(CancellationToken ct)
    {
        if (!IsConfigured || !OperatingSystem.IsWindows())
        {
            return [];
        }

        var psi = new ProcessStartInfo("certutil")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        // Discrete arguments: the CA config comes from configuration, not a shell.
        psi.ArgumentList.Add("-config");
        psi.ArgumentList.Add(CaConfig!);
        psi.ArgumentList.Add("-view");
        psi.ArgumentList.Add("-restrict");
        psi.ArgumentList.Add("Disposition=20,NotAfter>=now"); // issued and not yet expired
        psi.ArgumentList.Add("-out");
        psi.ArgumentList.Add(Columns);
        psi.ArgumentList.Add("csv");

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start certutil.");
        var stdout = process.StandardOutput.ReadToEndAsync(ct);
        var stderr = process.StandardError.ReadToEndAsync(ct);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(Timeout);
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
            throw new TimeoutException($"certutil -view against '{CaConfig}' did not finish within {Timeout}.");
        }
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"certutil -view against '{CaConfig}' exited {process.ExitCode}: {(await stderr).Trim()}");
        }

        var (list, skipped) = ParseCsvWithDiagnostics(await stdout);
        if (skipped > 0)
        {
            logger.LogWarning("AD CS: {Skipped} row(s) from {Ca} had dates certutil rendered in a format this host's locale could not parse and were skipped.", skipped, CaConfig);
        }
        logger.LogInformation("AD CS: read {Count} issued certificate(s) from {Ca}", list.Count, CaConfig);
        return list;
    }

    /// <summary>
    /// Parses certutil's CSV output: a header row of column display names, then one
    /// quoted-field row per certificate. Dates are in the machine's locale; rows that
    /// don't parse are skipped rather than failing the whole read.
    /// </summary>
    /// <summary>Upper bound on rows parsed from one CA, so a huge database can't exhaust memory.</summary>
    internal const int MaxRows = 20_000;

    internal static IReadOnlyList<AdcsCertificateDto> ParseCsv(string csv) => ParseCsvWithDiagnostics(csv).Certificates;

    internal static (IReadOnlyList<AdcsCertificateDto> Certificates, int SkippedUnparseable) ParseCsvWithDiagnostics(string csv)
    {
        var skipped = 0;
        var result = new List<AdcsCertificateDto>();
        var rows = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(SplitCsvRow)
            .Where(r => r.Count >= 5)
            .ToList();
        // First row is the header (localised display names); skip it.
        foreach (var row in rows.Skip(1))
        {
            var serial = row[0].Trim();
            if (serial.Length == 0 || serial.Equals("EMPTY", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            if (!TryParseDate(row[2], out var notBefore) || !TryParseDate(row[3], out var notAfter))
            {
                skipped++;
                continue;
            }
            if (result.Count >= MaxRows)
            {
                break;
            }
            var thumbprint = row[1].Replace(" ", "").Trim();
            result.Add(new AdcsCertificateDto(
                SerialNumber: serial,
                Thumbprint: thumbprint.Length == 40 ? thumbprint.ToUpperInvariant() : null,
                NotBefore: notBefore,
                NotAfter: notAfter,
                CommonName: NullIfEmpty(row[4]) ?? "",
                Template: row.Count > 5 ? NullIfEmpty(row[5]) : null,
                Requester: row.Count > 6 ? NullIfEmpty(row[6]) : null));
        }
        return (result, skipped);
    }

    /// <summary>
    /// certutil renders dates in the CA host's short date/time format. Try the
    /// current culture, then the shapes seen in the field, then invariant.
    /// </summary>
    private static readonly string[] KnownDateFormats =
    [
        "M/d/yyyy h:mm tt", "M/d/yyyy H:mm", "M/d/yyyy h:mm:ss tt", "M/d/yyyy H:mm:ss",
        "d/M/yyyy H:mm", "d/M/yyyy h:mm tt", "dd.MM.yyyy HH:mm", "dd.MM.yyyy HH:mm:ss",
        "yyyy-MM-dd HH:mm", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd", "dd/MM/yyyy HH:mm",
    ];

    private static bool TryParseDate(string text, out DateTimeOffset value)
    {
        var trimmed = text.Trim();
        if (DateTimeOffset.TryParse(trimmed, CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal, out value)
            || DateTimeOffset.TryParseExact(trimmed, KnownDateFormats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out value)
            || DateTimeOffset.TryParse(trimmed, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out value))
        {
            return true;
        }
        value = default;
        return false;
    }

    private static string? NullIfEmpty(string s) => string.IsNullOrWhiteSpace(s) || s.Trim() == "EMPTY" ? null : s.Trim();

    /// <summary>Splits one CSV row with double-quoted fields (quotes doubled inside).</summary>
    internal static List<string> SplitCsvRow(string row)
    {
        var fields = new List<string>();
        var field = new StringBuilder();
        var inQuotes = false;
        for (var i = 0; i < row.Length; i++)
        {
            var c = row[i];
            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < row.Length && row[i + 1] == '"')
                    {
                        field.Append('"');
                        i++;
                    }
                    else
                    {
                        inQuotes = false;
                    }
                }
                else
                {
                    field.Append(c);
                }
            }
            else if (c == '"')
            {
                inQuotes = true;
            }
            else if (c == ',')
            {
                fields.Add(field.ToString());
                field.Clear();
            }
            else
            {
                field.Append(c);
            }
        }
        fields.Add(field.ToString());
        return fields;
    }
}