using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace AcmeManager.Core.Security;

/// <summary>
/// Windows DPAPI implementation — machine scope, so the same service account
/// isn't required across reboots, but ciphertext is tied to the host. App
/// entropy adds a fixed salt distinct from any other DPAPI consumer.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiSecretProtector : ISecretProtector
{
    private static readonly byte[] AppEntropy = "AcmeManager.v1"u8.ToArray();

    public byte[] Protect(byte[] plaintext) =>
        ProtectedData.Protect(plaintext, AppEntropy, DataProtectionScope.LocalMachine);

    public byte[] Unprotect(byte[] ciphertext) =>
        ProtectedData.Unprotect(ciphertext, AppEntropy, DataProtectionScope.LocalMachine);
}