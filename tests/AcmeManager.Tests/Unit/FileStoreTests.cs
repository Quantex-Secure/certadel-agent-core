using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AcmeManager.Plugins.BuiltIn.Storage;
using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Storage;

using Microsoft.Extensions.Logging.Abstractions;

namespace AcmeManager.Tests.Unit;

public sealed class FileStoreTests : IDisposable
{
    private readonly string _tempDir;

    public FileStoreTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"acme-store-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }

    private static CertificateBundle MakeSelfSignedBundle(string cn = "test.example.com")
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest($"CN={cn}", ec, HashAlgorithmName.SHA256);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(cn);
        req.CertificateExtensions.Add(sanBuilder.Build());

        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(30));
        var pfx = cert.Export(X509ContentType.Pfx);

        return new CertificateBundle(
            CommonName: cn,
            SubjectAlternativeNames: [cn],
            PfxBytes: pfx,
            PfxPassword: "",
            NotBefore: cert.NotBefore,
            NotAfter: cert.NotAfter,
            Thumbprint: cert.Thumbprint);
    }

    [Fact]
    public async Task PfxFileStore_StoreThenRetrieve_RoundTrips()
    {
        var bundle = MakeSelfSignedBundle("pfx.test");
        var pfxPath = Path.Combine(_tempDir, "out.pfx");
        var store = new PfxFileStore(NullLogger<PfxFileStore>.Instance, new StubSecretResolver());
        var opts = new PfxFileStoreOptions { FilePath = pfxPath };

        var result = await store.StoreAsync(bundle, new StoreContext(opts), default);

        Assert.Equal(pfxPath, result.Reference);
        Assert.True(File.Exists(pfxPath));

        var retrieved = await store.RetrieveAsync(bundle.Thumbprint, new StoreContext(opts), default);
        Assert.NotNull(retrieved);
        Assert.Equal(bundle.Thumbprint, retrieved!.Thumbprint);
        Assert.Equal(bundle.CommonName, retrieved.CommonName);
    }

    [Fact]
    public async Task PfxFileStore_Delete_RemovesTheReferencedFile()
    {
        var bundle = MakeSelfSignedBundle();
        var pfxPath = Path.Combine(_tempDir, "del.pfx");
        var store = new PfxFileStore(NullLogger<PfxFileStore>.Instance, new StubSecretResolver());
        var opts = new PfxFileStoreOptions { FilePath = pfxPath };

        var result = await store.StoreAsync(bundle, new StoreContext(opts), default);
        Assert.True(File.Exists(pfxPath));

        // Delete acts on the reference StoreAsync returned (the path at store
        // time), so cleanup of an old cert can't remove a re-pointed config's file.
        await store.DeleteAsync(result.Reference, new StoreContext(opts), default);
        Assert.False(File.Exists(pfxPath));
    }

    [Fact]
    public async Task PfxFileStore_Delete_LeavesTheConfiguredFile_WhenReferencePointsElsewhere()
    {
        var bundle = MakeSelfSignedBundle();
        var pfxPath = Path.Combine(_tempDir, "keep.pfx");
        var store = new PfxFileStore(NullLogger<PfxFileStore>.Instance, new StubSecretResolver());
        var opts = new PfxFileStoreOptions { FilePath = pfxPath };

        await store.StoreAsync(bundle, new StoreContext(opts), default);

        await store.DeleteAsync(Path.Combine(_tempDir, "old-location.pfx"), new StoreContext(opts), default);
        Assert.True(File.Exists(pfxPath));
    }

    [Fact]
    public async Task PfxFileStore_ResolvesPasswordFromSecret_WhenPasswordSecretNameIsSet()
    {
        var bundle = MakeSelfSignedBundle("pfx-secret.test");
        var pfxPath = Path.Combine(_tempDir, "secret.pfx");
        var resolver = new StubSecretResolver(("pfx-pw", "s3cret"));
        var store = new PfxFileStore(NullLogger<PfxFileStore>.Instance, resolver);
        var opts = new PfxFileStoreOptions { FilePath = pfxPath, PasswordSecretName = "pfx-pw" };

        await store.StoreAsync(bundle, new StoreContext(opts), default);

        // The password came from the secret store, not a plaintext config field.
        Assert.True(resolver.Calls > 0);

        // The .pfx was written with the resolved password, so retrieving with the
        // same secret round-trips.
        var retrieved = await store.RetrieveAsync(bundle.Thumbprint, new StoreContext(opts), default);
        Assert.NotNull(retrieved);
        Assert.Equal(bundle.Thumbprint, retrieved!.Thumbprint);
    }

    private sealed class StubSecretResolver(params (string Name, string Value)[] values) : ISecretResolver
    {
        private readonly Dictionary<string, string> _values =
            values.ToDictionary(v => v.Name, v => v.Value, StringComparer.Ordinal);

        public int Calls { get; private set; }

        public Task<string> ResolveAsync(string name, CancellationToken ct)
        {
            Calls++;
            return _values.TryGetValue(name, out var value)
                ? Task.FromResult(value)
                : throw new KeyNotFoundException(name);
        }
    }

    [Fact]
    public async Task PemFileStore_Writes_FourExpectedFiles_WithCorrectShape()
    {
        var bundle = MakeSelfSignedBundle("pem.test");
        var store = new PemFileStore(NullLogger<PemFileStore>.Instance);
        var opts = new PemFileStoreOptions { DirectoryPath = _tempDir };

        var result = await store.StoreAsync(bundle, new StoreContext(opts), default);

        Assert.Equal(_tempDir, result.Reference);

        var certPem = await File.ReadAllTextAsync(Path.Combine(_tempDir, "cert.pem"));
        var chainPem = await File.ReadAllTextAsync(Path.Combine(_tempDir, "chain.pem"));
        var fullchainPem = await File.ReadAllTextAsync(Path.Combine(_tempDir, "fullchain.pem"));
        var privkeyPem = await File.ReadAllTextAsync(Path.Combine(_tempDir, "privkey.pem"));

        Assert.Contains("BEGIN CERTIFICATE", certPem);
        // Self-signed has no intermediates, so chain.pem is empty.
        Assert.True(string.IsNullOrEmpty(chainPem.Trim()));
        Assert.Contains("BEGIN CERTIFICATE", fullchainPem);
        Assert.Contains("BEGIN PRIVATE KEY", privkeyPem);
    }

    [Fact]
    public async Task PemFileStore_BaseName_PrefixesTheFileNames()
    {
        var bundle = MakeSelfSignedBundle("pem.test");
        var store = new PemFileStore(NullLogger<PemFileStore>.Instance);
        var opts = new PemFileStoreOptions { DirectoryPath = _tempDir, BaseName = "HAProxy" };

        await store.StoreAsync(bundle, new StoreContext(opts), default);

        Assert.True(File.Exists(Path.Combine(_tempDir, "HAProxy-cert.pem")));
        Assert.True(File.Exists(Path.Combine(_tempDir, "HAProxy-chain.pem")));
        Assert.True(File.Exists(Path.Combine(_tempDir, "HAProxy-fullchain.pem")));
        Assert.True(File.Exists(Path.Combine(_tempDir, "HAProxy-privkey.pem")));
        // The unprefixed certbot names are NOT written when a base name is set.
        Assert.False(File.Exists(Path.Combine(_tempDir, "cert.pem")));

        // Delete uses the same naming and cleans them up.
        await store.DeleteAsync(_tempDir, new StoreContext(opts), default);
        Assert.False(File.Exists(Path.Combine(_tempDir, "HAProxy-fullchain.pem")));
    }
}