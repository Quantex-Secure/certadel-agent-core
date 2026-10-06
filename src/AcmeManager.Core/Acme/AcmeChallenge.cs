namespace AcmeManager.Core.Acme;

public enum ChallengeStatus
{
    Pending,
    Processing,
    Valid,
    Invalid,
}

public static class AcmeChallengeTypes
{
    public const string Http01 = "http-01";
    public const string Dns01 = "dns-01";
    public const string TlsAlpn01 = "tls-alpn-01";
}

/// <summary>
/// A single challenge offered by the CA for an authorization. The engine picks
/// one (matching the configured validator plugin) and asks the CA to validate
/// it via <c>IAcmeClient.SubmitChallengeAsync</c>. <see cref="AuthorizationUrl"/>
/// is carried so the client can re-fetch the parent authorization context when
/// submitting — Certes doesn't expose a directory-level "get challenge by URL".
/// </summary>
public sealed record AcmeChallenge(
    Uri Url,
    Uri AuthorizationUrl,
    string Type,
    string Token,
    ChallengeStatus Status,
    string? Error = null);