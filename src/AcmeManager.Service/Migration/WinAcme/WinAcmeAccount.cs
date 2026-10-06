using System.Security.Cryptography;
using System.Text.Json.Nodes;

using Certes;

namespace AcmeManager.Service.Migration.WinAcme;

/// <summary>An acme-manager account reconstructed from a win-acme Signer_v2 + Registration_v2.</summary>
internal sealed record ImportedAccount(string Pem, string KeyId, string DirectoryUrl, string ContactEmail);

/// <summary>
/// Converts win-acme's account files into an acme-manager account so renewals can
/// keep running under the <b>same</b> ACME account (same key → same registered
/// account URL/KID). win-acme stores the account key in <c>Signer_v2</c> (a
/// ProtectedString wrapping <c>{ KeyType, KeyExport }</c>, where KeyExport is
/// ACMESharp's <c>{ HashSize, D, X, Y }</c> base64 EC params) and the account URL
/// in <c>Registration_v2</c>. We rebuild the EC key, then round-trip it through
/// Certes so the stored PEM is exactly what acme-manager reads back.
/// </summary>
internal static class WinAcmeAccount
{
    public static ImportedAccount? Convert(string? signerRaw, JsonObject? registration)
    {
        if (string.IsNullOrEmpty(signerRaw) || registration is null) return null;

        var dec = WinAcmeProtectedString.Decode(signerRaw);
        if (dec.Kind != WinAcmeProtectedString.Kind.Plain || string.IsNullOrEmpty(dec.Value)) return null;

        if (JsonNode.Parse(dec.Value) is not JsonObject outer) return null;
        var keyType = Str(outer, "KeyType");
        var keyExport = Str(outer, "KeyExport");
        if (string.IsNullOrEmpty(keyType) || string.IsNullOrEmpty(keyExport)) return null;

        if (!keyType.StartsWith("ES", StringComparison.OrdinalIgnoreCase))
        {
            throw new NotSupportedException($"win-acme account key type '{keyType}' import isn't supported yet (only ES256/384/512).");
        }

        var pem = EcPem(keyExport);
        var kid = Str(registration, "Kid") ?? Str(registration, "Location")
            ?? throw new InvalidOperationException("Registration_v2 has no account URL (Kid/Location).");
        return new ImportedAccount(pem, kid, DeriveDirectory(kid), ExtractContact(registration));
    }

    private static string EcPem(string exportJson)
    {
        if (JsonNode.Parse(exportJson) is not JsonObject d)
        {
            throw new InvalidOperationException("Signer KeyExport is not valid JSON.");
        }

        var hashSize = d["HashSize"]?.GetValue<int>() ?? 256;
        var curve = hashSize switch
        {
            384 => ECCurve.NamedCurves.nistP384,
            512 or 521 => ECCurve.NamedCurves.nistP521,
            _ => ECCurve.NamedCurves.nistP256,
        };

        var ecParams = new ECParameters
        {
            Curve = curve,
            D = System.Convert.FromBase64String(Req(d, "D")),
            Q = new ECPoint
            {
                X = System.Convert.FromBase64String(Req(d, "X")),
                Y = System.Convert.FromBase64String(Req(d, "Y")),
            },
        };

        using var ec = ECDsa.Create();
        ec.ImportParameters(ecParams);

        // Round-trip through Certes so the stored PEM is exactly the shape it reads.
        foreach (var candidate in new[] { ec.ExportECPrivateKeyPem(), ec.ExportPkcs8PrivateKeyPem() })
        {
            try { return KeyFactory.FromPem(candidate).ToPem(); }
            catch { /* try the next encoding */ }
        }
        throw new InvalidOperationException("Certes could not load the reconstructed EC account key.");
    }

    private static string DeriveDirectory(string accountUrl)
    {
        var u = new Uri(accountUrl);
        return $"{u.Scheme}://{u.Host}/directory";
    }

    private static string ExtractContact(JsonObject registration)
    {
        var contacts = (registration["Payload"] as JsonObject)?["contact"] as JsonArray;
        var first = contacts?.Select(c => c is null ? null : Try(c)).FirstOrDefault(s => !string.IsNullOrEmpty(s));
        return first?.Replace("mailto:", "", StringComparison.OrdinalIgnoreCase) ?? "";
    }

    private static string Req(JsonObject o, string name) =>
        Str(o, name) ?? throw new InvalidOperationException($"Signer KeyExport is missing '{name}'.");

    private static string? Str(JsonObject o, string name) => o[name] is { } n ? Try(n) : null;

    private static string? Try(JsonNode n)
    {
        try { return n.GetValue<string>(); } catch { return n.ToString(); }
    }
}