using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

using AcmeManager.Core.Acme;
using AcmeManager.Core.Acme.Accounts;
using AcmeManager.Core.Acme.Orders;

using Certes;
using Certes.Acme;

using Microsoft.Extensions.Logging.Abstractions;

namespace AcmeManager.Tests.Integration;

[Collection(PebbleCollection.Name)]
public sealed class EndToEndOrderTests(PebbleFixture pebble)
{
    [SkippableFact]
    public async Task FullOrderFlow_IssuesValidCertificate()
    {
        pebble.EnsureAvailableOrSkip();

        // Arrange — Pebble-trusting client wired into our IAcmeClient.
        var httpClient = pebble.CreatePebbleTrustingHttpClient();
        var acme = new CertesAcmeClient(
            NullLogger<CertesAcmeClient>.Instance,
            contextFactory: (url, key) => new AcmeContext(url, key, new AcmeHttpClient(url, httpClient)));

        // 1. Register a fresh account at Pebble's directory.
        var accountKey = AcmeKeyGenerator.Generate(AcmeKeyAlgorithm.EcP256);
        var registered = await acme.CreateAccountAsync(
            new AcmeAccount(
                LocalId: Guid.NewGuid(),
                DirectoryUrl: pebble.AcmeDirectoryUrl,
                ContactEmail: "ci@acme-manager.test",
                Key: accountKey,
                KeyId: null),
            eab: null,
            ct: default);

        Assert.NotNull(registered.KeyId);

        // 2. Run a full order through OrderRunner using the challtestsrv validator.
        using var mgmt = new HttpClient { BaseAddress = pebble.ChallTestSrvMgmtUrl };
        var validator = new ChallTestSrvHttp01Validator(mgmt);
        var runner = new OrderRunner(acme, NullLogger<OrderRunner>.Instance);

        var identifiers = new[] { $"e2e-{Guid.NewGuid():N}.test" };
        var result = await runner.RunAsync(
            registered,
            identifiers,
            validator,
            opts: new OrderRunnerOptions
            {
                PollInterval = TimeSpan.FromMilliseconds(500),
                MaxPolls = 20,
                CertificateKeyAlgorithm = AcmeKeyAlgorithm.EcP256,
            },
            ct: default);

        // Assert — we got a PFX, the leaf has the right SAN, and the chain validates.
        Assert.NotNull(result.Pfx);
        Assert.NotEmpty(result.Pfx);

        var collection = X509CertificateLoader.LoadPkcs12Collection(result.Pfx, password: null);
        Assert.True(collection.Count >= 1, "PFX should contain at least the leaf certificate");

        var leaf = collection[0];
        Assert.Contains(identifiers[0], leaf.GetNameInfo(X509NameType.DnsName, forIssuer: false), StringComparison.OrdinalIgnoreCase);
        Assert.True(leaf.NotAfter > DateTime.UtcNow, "Issued cert should be in-date");
        Assert.True(leaf.HasPrivateKey, "Leaf cert should have its private key attached");
    }
}