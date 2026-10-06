namespace AcmeManager.Core.Discovery;

/// <summary>
/// Whether this node advertises itself on the local network (mDNS). A stored
/// choice (<see cref="Key"/> in the Settings table) wins; otherwise the host's
/// default applies — on, except where the packaging turns it off
/// (<see cref="EnabledByDefaultConfigKey"/>), as the Synology package does so a
/// NAS stays quiet on the network until its owner opts in.
/// </summary>
public static class DiscoverySettings
{
    public const string Key = "discovery.enabled";

    public const string EnabledByDefaultConfigKey = "Discovery:EnabledByDefault";

    public static bool IsEnabled(string? storedValue, bool enabledByDefault) =>
        storedValue is null
            ? enabledByDefault
            : !string.Equals(storedValue, "false", StringComparison.OrdinalIgnoreCase);
}
