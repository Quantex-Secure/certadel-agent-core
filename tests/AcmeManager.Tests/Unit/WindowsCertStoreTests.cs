using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

using AcmeManager.Plugins.BuiltIn.Storage;
using AcmeManager.Plugins.Contracts.Storage;

using Microsoft.Extensions.Logging.Abstractions;

namespace AcmeManager.Tests.Unit;

public sealed class WindowsCertStoreTests
{
    // The round-trip tests import a PFX with MachineKeySet (the store's real
    // behavior), which writes the private key to the machine key store and
    // therefore needs an elevated process. Skip rather than fail when we can't —
    // e.g. a non-elevated dev box. Elevated runners (incl. GitHub's) still run it.
    private static bool CanWriteMachineKeys()
    {
        if (!OperatingSystem.IsWindows())
            return false;

        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    // ---------------- ResolveFriendlyName (portable) ----------------

    [Fact]
    public void ResolveFriendlyName_PrefersExplicitOption()
    {
        var name = WindowsCertStore.ResolveFriendlyName(
            new WindowsCertStoreOptions { FriendlyName = "Explicit" },
            Bundle(friendlyName: "Renewal Name"));

        Assert.Equal("Explicit", name);
    }

    [Fact]
    public void ResolveFriendlyName_FallsBackToBundleRenewalName()
    {
        var name = WindowsCertStore.ResolveFriendlyName(
            new WindowsCertStoreOptions(),
            Bundle(friendlyName: "[IIS] Block Drop, (any host)"));

        Assert.Equal("[IIS] Block Drop, (any host)", name);
    }

    [Fact]
    public void ResolveFriendlyName_EmptyWhenNeitherSet()
    {
        var name = WindowsCertStore.ResolveFriendlyName(
            new WindowsCertStoreOptions(),
            Bundle(friendlyName: ""));

        Assert.Equal("", name);
    }

    // ---------------- Round-trip (Windows only) ----------------

    [SkippableFact]
    public async Task StoreAsync_StampsTheFriendlyName_OnTheStoredCert()
    {
        Skip.IfNot(CanWriteMachineKeys(), "Windows cert-store import needs an elevated process");

        var store = new WindowsCertStore(NullLogger<WindowsCertStore>.Instance);
        // CurrentUser\My is writable without elevation; keep the test self-contained.
        var opts = new WindowsCertStoreOptions { Location = StoreLocation.CurrentUser, StoreName = "My" };
        var ctx = new StoreContext(opts);
        var bundle = Bundle(friendlyName: "Block Drop");

        try
        {
            var result = await store.StoreAsync(bundle, ctx, default);

            using var x509 = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            x509.Open(OpenFlags.ReadOnly);
            var found = x509.Certificates.Find(X509FindType.FindByThumbprint, result.Reference, validOnly: false);
            var stored = Assert.Single(found.OfType<X509Certificate2>());
            Assert.Equal("Block Drop", stored.FriendlyName);
        }
        finally
        {
            await store.DeleteAsync(bundle.Thumbprint, ctx, default);
        }
    }

    [SkippableFact]
    public async Task StoreAsync_ExplicitOptionOverridesRenewalName_OnTheStoredCert()
    {
        Skip.IfNot(CanWriteMachineKeys(), "Windows cert-store import needs an elevated process");

        var store = new WindowsCertStore(NullLogger<WindowsCertStore>.Instance);
        var opts = new WindowsCertStoreOptions
        {
            Location = StoreLocation.CurrentUser,
            StoreName = "My",
            FriendlyName = "Override Label",
        };
        var ctx = new StoreContext(opts);
        var bundle = Bundle(friendlyName: "Renewal Name");

        try
        {
            var result = await store.StoreAsync(bundle, ctx, default);

            using var x509 = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            x509.Open(OpenFlags.ReadOnly);
            var found = x509.Certificates.Find(X509FindType.FindByThumbprint, result.Reference, validOnly: false);
            var stored = Assert.Single(found.OfType<X509Certificate2>());
            Assert.Equal("Override Label", stored.FriendlyName);
        }
        finally
        {
            await store.DeleteAsync(bundle.Thumbprint, ctx, default);
        }
    }

    [SkippableFact]
    public async Task StoreAsync_DoesNotRemoveCertsWhoseNameMerelyContainsTheNewName()
    {
        Skip.IfNot(CanWriteMachineKeys(), "Windows cert-store import needs an elevated process");

        // Regression: "apples.<x>" is a substring of "fallingapples.<x>". The old
        // FindBySubjectName supersede removed the longer-named cert; exact-match must not.
        var store = new WindowsCertStore(NullLogger<WindowsCertStore>.Instance);
        var opts = new WindowsCertStoreOptions { Location = StoreLocation.CurrentUser, StoreName = "My" };
        var ctx = new StoreContext(opts);
        var suffix = $"regress-{Guid.NewGuid():N}.test";
        var longCert = ExactCnBundle($"fallingapples.{suffix}");
        var shortCert = ExactCnBundle($"apples.{suffix}");

        try
        {
            await store.StoreAsync(longCert, ctx, default);
            await store.StoreAsync(shortCert, ctx, default); // its supersede must NOT delete the long one

            using var x509 = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            x509.Open(OpenFlags.ReadOnly);
            Assert.Single(x509.Certificates.Find(X509FindType.FindByThumbprint, longCert.Thumbprint, false)
                .OfType<X509Certificate2>());
        }
        finally
        {
            await store.DeleteAsync(longCert.Thumbprint, ctx, default);
            await store.DeleteAsync(shortCert.Thumbprint, ctx, default);
        }
    }

    private static CertificateBundle ExactCnBundle(string cn)
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest($"CN={cn}", ec, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(cn);
        req.CertificateExtensions.Add(san.Build());
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));
        return new CertificateBundle(cn, [cn], cert.Export(X509ContentType.Pfx), "",
            cert.NotBefore, cert.NotAfter, cert.Thumbprint);
    }

    private static CertificateBundle Bundle(string friendlyName, string cn = "friendly.test")
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest($"CN={cn}-{Guid.NewGuid():N}", ec, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));
        var pfx = cert.Export(X509ContentType.Pfx);

        return new CertificateBundle(
            CommonName: cn,
            SubjectAlternativeNames: [cn],
            PfxBytes: pfx,
            PfxPassword: "",
            NotBefore: cert.NotBefore,
            NotAfter: cert.NotAfter,
            Thumbprint: cert.Thumbprint)
        {
            FriendlyName = friendlyName,
        };
    }
}