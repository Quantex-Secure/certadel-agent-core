namespace AcmeManager.Core.Security;

/// <summary>
/// Encrypts and decrypts byte arrays for at-rest secret storage in the SQLite
/// database. Implementations are OS-specific:
/// <list type="bullet">
///   <item>Windows: DPAPI (machine scope) — bound to the local machine.</item>
///   <item>Linux: libsecret if present, else an AES-GCM keyfile in the data dir.</item>
/// </list>
/// Resolved from DI at startup based on the running OS.
/// </summary>
public interface ISecretProtector
{
    byte[] Protect(byte[] plaintext);

    byte[] Unprotect(byte[] ciphertext);
}