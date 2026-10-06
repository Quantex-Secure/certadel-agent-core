using AcmeManager.Plugins.BuiltIn.Storage;
using AcmeManager.Plugins.Iis;

using Microsoft.Extensions.Logging.Abstractions;

namespace AcmeManager.Tests.Unit;

/// <summary>
/// Confirms platform-conditional plugins report capability matching the
/// running OS — the engine's <c>EnsureAvailableAsync</c> guard is the
/// runtime backstop that keeps them out of action on the wrong platform.
/// </summary>
public sealed class PluginCapabilityTests
{
    [Fact]
    public async Task IisSource_CapabilityMatchesOs()
    {
        var plugin = new IisSource(NullLogger<IisSource>.Instance);
        var result = await plugin.CheckAsync(default);
        Assert.Equal(OperatingSystem.IsWindows(), result.Available);
        if (!result.Available)
        {
            Assert.Contains("Windows", result.Reason!);
        }
    }

    [Fact]
    public async Task IisInstaller_CapabilityMatchesOs()
    {
        var plugin = new IisInstaller(NullLogger<IisInstaller>.Instance);
        var result = await plugin.CheckAsync(default);
        Assert.Equal(OperatingSystem.IsWindows(), result.Available);
    }

    [Fact]
    public async Task WindowsCertStore_CapabilityMatchesOs()
    {
        var plugin = new WindowsCertStore(NullLogger<WindowsCertStore>.Instance);
        var result = await plugin.CheckAsync(default);
        Assert.Equal(OperatingSystem.IsWindows(), result.Available);
    }
}