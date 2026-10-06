namespace AcmeManager.Api.Contracts;

/// <summary>
/// Version identifier and route paths for the agent's v1 management API. Both
/// the agent (route registration) and the Unified Certificate Manager client
/// reference these constants so the wire contract has a single source of truth.
/// </summary>
public static class ApiV1
{
    public const string Version = "v1";

    public const string Base = "/api/v1";

    public const string Agent = Base + "/agent";

    public const string Certificates = Base + "/certificates";

    public const string Renewals = Base + "/renewals";

    public const string Accounts = Base + "/accounts";

    public const string Secrets = Base + "/secrets";

    public const string Plugins = Base + "/plugins";

    public const string IisSites = Base + "/iis-sites";

    public const string CertStores = Base + "/cert-stores";

    public const string History = Base + "/history";

    public const string Logs = Base + "/logs";

    public const string DnsProviders = Base + "/dns-providers";

    /// <summary>What this agent's host serves, reconciled against what renews it.</summary>
    public const string Coverage = Base + "/coverage";

    /// <summary>Certificates issued by the internal AD CS CA the agent is configured to read (empty if none).</summary>
    public const string AdcsCertificates = Base + "/adcs-certificates";

    public static string Renewal(Guid id) => $"{Renewals}/{id}";

    public static string RenewalConfig(Guid id) => $"{Renewals}/{id}/config";

    public static string Renew(Guid id) => $"{Renewals}/{id}/renew";

    public static string Enable(Guid id) => $"{Renewals}/{id}/enable";

    public static string Disable(Guid id) => $"{Renewals}/{id}/disable";
}