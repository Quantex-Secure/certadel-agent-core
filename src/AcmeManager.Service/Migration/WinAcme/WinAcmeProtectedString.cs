using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace AcmeManager.Service.Migration.WinAcme;

/// <summary>
/// Decodes win-acme's <c>ProtectedString</c> on-disk format, used for renewal
/// secrets (Azure client secret, PFX passwords) and the account signer file.
/// Format (from win-acme src/main.lib/Services/Serialization/ProtectedString.cs):
/// <list type="bullet">
///   <item><c>enc-&lt;base64&gt;</c> — DPAPI-protected (null entropy, LocalMachine scope), base64</item>
///   <item><c>clear-&lt;text&gt;</c> — literal plaintext after the prefix</item>
///   <item><c>vault://...</c> — reference into win-acme's secret vault (not inline)</item>
///   <item>anything else — plain base64 of the UTF-8 value</item>
/// </list>
/// Because win-acme uses the <b>LocalMachine</b> DPAPI scope, <c>enc-</c> values
/// decrypt on the same machine regardless of which account runs the importer.
/// </summary>
internal static class WinAcmeProtectedString
{
    public const string VaultPrefix = "vault://";

    public enum Kind { Plain, Vault, Undecryptable, Empty }

    public readonly record struct Decoded(Kind Kind, string? Value, string? Note);

    public static Decoded Decode(string? raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return new Decoded(Kind.Empty, null, null);
        }

        if (raw.StartsWith("clear-", StringComparison.Ordinal))
        {
            return new Decoded(Kind.Plain, raw["clear-".Length..], null);
        }

        if (raw.StartsWith(VaultPrefix, StringComparison.Ordinal))
        {
            // Lives in win-acme's vault.json, not in the renewal — caller resolves or flags it.
            return new Decoded(Kind.Vault, raw, "stored in win-acme secret vault; not inline");
        }

        if (raw.StartsWith("enc-", StringComparison.Ordinal))
        {
            if (!OperatingSystem.IsWindows())
            {
                return new Decoded(Kind.Undecryptable, null, "DPAPI value; can only be decrypted on Windows on the original host");
            }
            try
            {
                return new Decoded(Kind.Plain, Unprotect(raw["enc-".Length..]), null);
            }
            catch (Exception ex)
            {
                return new Decoded(Kind.Undecryptable, null,
                    $"DPAPI decrypt failed ({ex.GetType().Name}) — run on the original host as a user/SYSTEM with machine-key access");
            }
        }

        // Unmarked: plain base64.
        try
        {
            return new Decoded(Kind.Plain, Encoding.UTF8.GetString(Convert.FromBase64String(raw)), null);
        }
        catch (FormatException)
        {
            // Not base64 — treat as literal text.
            return new Decoded(Kind.Plain, raw, null);
        }
    }

    [SupportedOSPlatform("windows")]
    private static string Unprotect(string base64) =>
        Encoding.UTF8.GetString(
            ProtectedData.Unprotect(Convert.FromBase64String(base64), optionalEntropy: null, DataProtectionScope.LocalMachine));
}