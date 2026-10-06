using System.Security.Cryptography;

namespace AcmeManager.Core.Security;

/// <summary>
/// Cross-platform AES-256-GCM protector. The 32-byte master key is read from
/// (or generated on first use into) a file on disk. On Unix the keyfile is
/// chmod'd 0600. Format of each ciphertext: nonce(12) ‖ ciphertext(n) ‖ tag(16).
///
/// Deleting or corrupting the keyfile renders all stored secrets
/// unrecoverable — same threat model as DPAPI.
/// </summary>
public sealed class AesGcmFileSecretProtector : ISecretProtector
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;

    private readonly byte[] _key;

    public AesGcmFileSecretProtector(string keyFilePath)
    {
        _key = LoadOrCreateKey(keyFilePath);
    }

    public byte[] Protect(byte[] plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using var gcm = new AesGcm(_key, TagSize);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag);

        var output = new byte[NonceSize + ciphertext.Length + TagSize];
        Buffer.BlockCopy(nonce, 0, output, 0, NonceSize);
        Buffer.BlockCopy(ciphertext, 0, output, NonceSize, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, output, NonceSize + ciphertext.Length, TagSize);
        return output;
    }

    public byte[] Unprotect(byte[] ciphertext)
    {
        if (ciphertext.Length < NonceSize + TagSize)
        {
            throw new CryptographicException("Ciphertext too short");
        }

        var nonce = ciphertext.AsSpan(0, NonceSize);
        var actualCipher = ciphertext.AsSpan(NonceSize, ciphertext.Length - NonceSize - TagSize);
        var tag = ciphertext.AsSpan(ciphertext.Length - TagSize, TagSize);

        var plaintext = new byte[actualCipher.Length];
        using var gcm = new AesGcm(_key, TagSize);
        gcm.Decrypt(nonce, actualCipher, tag, plaintext);
        return plaintext;
    }

    private static byte[] LoadOrCreateKey(string path)
    {
        if (File.Exists(path))
        {
            var existing = File.ReadAllBytes(path);
            if (existing.Length != KeySize)
            {
                throw new CryptographicException(
                    $"Secrets key at '{path}' is corrupt (expected {KeySize} bytes, got {existing.Length}).");
            }
            return existing;
        }

        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var key = RandomNumberGenerator.GetBytes(KeySize);
        File.WriteAllBytes(path, key);

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        return key;
    }
}