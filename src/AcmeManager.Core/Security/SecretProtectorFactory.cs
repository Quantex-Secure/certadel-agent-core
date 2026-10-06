namespace AcmeManager.Core.Security;

public static class SecretProtectorFactory
{
    /// <summary>
    /// Returns <see cref="DpapiSecretProtector"/> on Windows, otherwise
    /// <see cref="AesGcmFileSecretProtector"/> backed by the given keyfile.
    /// </summary>
    public static ISecretProtector Create(string aesKeyFilePath)
    {
        if (OperatingSystem.IsWindows())
        {
            return new DpapiSecretProtector();
        }

        return new AesGcmFileSecretProtector(aesKeyFilePath);
    }
}