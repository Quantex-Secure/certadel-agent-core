using AcmeManager.Plugins.BuiltIn.Installation;
using AcmeManager.Plugins.Contracts.Installation;
using AcmeManager.Plugins.Contracts.Storage;

using Microsoft.Extensions.Logging.Abstractions;

namespace AcmeManager.Tests.Unit;

public sealed class ScriptInstallerTests : IDisposable
{
    private readonly string _tempDir;

    public ScriptInstallerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"acme-script-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }

    private static CertificateBundle MakeBundle() => new(
        CommonName: "scripted.example.com",
        SubjectAlternativeNames: ["scripted.example.com", "www.scripted.example.com"],
        PfxBytes: [1, 2, 3],
        PfxPassword: "",
        NotBefore: DateTimeOffset.UtcNow,
        NotAfter: DateTimeOffset.UtcNow.AddDays(90),
        Thumbprint: "DEADBEEF");

    [SkippableFact]
    public async Task ScriptInstaller_PassesEnvVars_ToBatchScript()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "Uses Windows .cmd interpreter");

        var capturePath = Path.Combine(_tempDir, "captured.txt");
        var scriptPath = Path.Combine(_tempDir, "capture.cmd");
        await File.WriteAllTextAsync(scriptPath,
            $"@echo off\r\n" +
            $"(echo CN=%ACME_COMMON_NAME%& echo SAN0=%ACME_SAN_0%& echo STORE=%ACME_STORE_STORE_PFX%) > \"{capturePath}\"\r\n");

        var installer = new ScriptInstaller(NullLogger<ScriptInstaller>.Instance);
        var opts = new ScriptInstallerOptions { ScriptPath = scriptPath };
        var storeRefs = new Dictionary<string, string> { ["store.pfx"] = "C:/tmp/foo.pfx" };

        await installer.InstallAsync(MakeBundle(), new InstallContext(opts, storeRefs), default);

        var captured = await File.ReadAllTextAsync(capturePath);
        Assert.Contains("CN=scripted.example.com", captured);
        Assert.Contains("SAN0=scripted.example.com", captured);
        Assert.Contains("STORE=C:/tmp/foo.pfx", captured);
    }

    [SkippableFact]
    public async Task ScriptInstaller_PassesEnvVars_ToShellScript()
    {
        Skip.If(OperatingSystem.IsWindows(), "Uses /bin/sh");

        var capturePath = Path.Combine(_tempDir, "captured.txt");
        var scriptPath = Path.Combine(_tempDir, "capture.sh");
        await File.WriteAllTextAsync(scriptPath,
            $"#!/bin/sh\necho \"CN=$ACME_COMMON_NAME SAN0=$ACME_SAN_0 STORE=$ACME_STORE_STORE_PFX\" > \"{capturePath}\"\n");
#pragma warning disable CA1416 // Skip.If above guards this against Windows
        File.SetUnixFileMode(scriptPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
#pragma warning restore CA1416

        var installer = new ScriptInstaller(NullLogger<ScriptInstaller>.Instance);
        var opts = new ScriptInstallerOptions { ScriptPath = scriptPath };
        var storeRefs = new Dictionary<string, string> { ["store.pfx"] = "/tmp/foo.pfx" };

        await installer.InstallAsync(MakeBundle(), new InstallContext(opts, storeRefs), default);

        var captured = await File.ReadAllTextAsync(capturePath);
        Assert.Contains("CN=scripted.example.com", captured);
        Assert.Contains("SAN0=scripted.example.com", captured);
        Assert.Contains("STORE=/tmp/foo.pfx", captured);
    }

    [Fact]
    public async Task ScriptInstaller_NonZeroExit_Throws()
    {
        var scriptPath = Path.Combine(_tempDir,
            OperatingSystem.IsWindows() ? "fail.cmd" : "fail.sh");
        if (OperatingSystem.IsWindows())
        {
            await File.WriteAllTextAsync(scriptPath, "@echo error 1>&2\r\nexit /b 17\r\n");
        }
        else
        {
            await File.WriteAllTextAsync(scriptPath, "#!/bin/sh\necho error >&2\nexit 17\n");
#pragma warning disable CA1416 // analyzer doesn't track if/else inversion across branches
            File.SetUnixFileMode(scriptPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
#pragma warning restore CA1416
        }

        var installer = new ScriptInstaller(NullLogger<ScriptInstaller>.Instance);
        var opts = new ScriptInstallerOptions { ScriptPath = scriptPath };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => installer.InstallAsync(MakeBundle(), new InstallContext(opts, new Dictionary<string, string>()), default).AsTask());

        Assert.Contains("17", ex.Message);
    }

    [Fact]
    public async Task ScriptInstaller_MissingScript_Throws()
    {
        var installer = new ScriptInstaller(NullLogger<ScriptInstaller>.Instance);
        var opts = new ScriptInstallerOptions { ScriptPath = Path.Combine(_tempDir, "nope.sh") };

        await Assert.ThrowsAsync<FileNotFoundException>(
            () => installer.InstallAsync(MakeBundle(), new InstallContext(opts, new Dictionary<string, string>()), default).AsTask());
    }
}