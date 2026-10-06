using AcmeManager.Core.Acme;

namespace AcmeManager.Tests.Unit;

public sealed class AcmeChainPemTests
{
    private const string Leaf =
        "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----";
    private const string Intermediate =
        "-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----";

    [Fact]
    public void AssembleChainPem_PutsLeafFirst_ThenIssuers()
    {
        var pem = CertesAcmeClient.AssembleChainPem(Leaf, [Intermediate]);

        var leafIdx = pem.IndexOf("LEAF", StringComparison.Ordinal);
        var interIdx = pem.IndexOf("INTERMEDIATE", StringComparison.Ordinal);
        Assert.True(leafIdx >= 0 && interIdx >= 0);
        Assert.True(leafIdx < interIdx, "leaf must come before the intermediate");

        // Two well-formed cert blocks, newline-separated (so the PFX splitter sees both).
        Assert.Equal(2, CountOccurrences(pem, "-----BEGIN CERTIFICATE-----"));
        Assert.Equal(2, CountOccurrences(pem, "-----END CERTIFICATE-----"));
    }

    [Fact]
    public void AssembleChainPem_LeafOnly_NoIssuers_Works()
    {
        var pem = CertesAcmeClient.AssembleChainPem(Leaf, []);

        Assert.Equal(1, CountOccurrences(pem, "-----BEGIN CERTIFICATE-----"));
        Assert.EndsWith("\n", pem);
    }

    private static int CountOccurrences(string haystack, string needle)
    {
        var count = 0;
        for (var i = haystack.IndexOf(needle, StringComparison.Ordinal); i >= 0;
             i = haystack.IndexOf(needle, i + needle.Length, StringComparison.Ordinal))
        {
            count++;
        }
        return count;
    }
}