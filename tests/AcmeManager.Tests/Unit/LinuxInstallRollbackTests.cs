using AcmeManager.Plugins.Linux;

namespace AcmeManager.Tests.Unit;

/// <summary>The write-with-undo primitive every Linux installer hands the engine as its rollback.</summary>
public sealed class LinuxInstallRollbackTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"acme-rollback-{Guid.NewGuid():N}");

    public LinuxInstallRollbackTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    [Fact]
    public void Restore_PutsThePreviousContentBack()
    {
        var path = Path.Combine(_dir, "site.pem");
        File.WriteAllText(path, "OLD");

        var restore = LinuxInstall.WriteFileAtomicKeepingPrevious(path, "NEW", ownerOnly: true);
        Assert.Equal("NEW", File.ReadAllText(path));

        restore();

        Assert.Equal("OLD", File.ReadAllText(path));
        Assert.False(File.Exists(path + ".tmp"));
    }

    [Fact]
    public void Restore_RemovesTheFile_WhenThereWasNoneBefore()
    {
        var path = Path.Combine(_dir, "fresh.pem");

        var restore = LinuxInstall.WriteFileAtomicKeepingPrevious(path, "NEW", ownerOnly: false);
        Assert.True(File.Exists(path));

        restore();

        Assert.False(File.Exists(path));
    }

    [Fact]
    public void Restore_CanRunTwice_WithoutFailing()
    {
        var path = Path.Combine(_dir, "twice.pem");
        File.WriteAllText(path, "OLD");
        var restore = LinuxInstall.WriteFileAtomicKeepingPrevious(path, "NEW", ownerOnly: false);

        restore();
        restore();

        Assert.Equal("OLD", File.ReadAllText(path));
    }
}