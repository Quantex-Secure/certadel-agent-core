using Certes;

namespace AcmeManager.Core.Acme.Accounts;

public static class AcmeKeyGenerator
{
    /// <summary>Generates a fresh account key of the requested algorithm.</summary>
    public static AcmeAccountKey Generate(AcmeKeyAlgorithm algorithm)
    {
        var certesAlg = algorithm switch
        {
            AcmeKeyAlgorithm.Rsa2048 => KeyAlgorithm.RS256,
            AcmeKeyAlgorithm.EcP256 => KeyAlgorithm.ES256,
            AcmeKeyAlgorithm.EcP384 => KeyAlgorithm.ES384,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null),
        };

        var key = KeyFactory.NewKey(certesAlg);
        return new AcmeAccountKey(key.ToPem());
    }
}