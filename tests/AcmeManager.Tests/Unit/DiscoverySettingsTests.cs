using AcmeManager.Core.Discovery;

namespace AcmeManager.Tests.Unit;

public sealed class DiscoverySettingsTests
{
    [Theory]
    [InlineData(null, true, true)]      // nothing stored: the host's default
    [InlineData(null, false, false)]    // e.g. Synology DSM ships with discovery off
    [InlineData("true", false, true)]   // an explicit choice wins over the default
    [InlineData("TRUE", false, true)]
    [InlineData("false", true, false)]
    [InlineData("False", true, false)]
    public void StoredChoice_OverridesTheHostDefault(string? stored, bool enabledByDefault, bool expected) =>
        Assert.Equal(expected, DiscoverySettings.IsEnabled(stored, enabledByDefault));
}
