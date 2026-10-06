namespace AcmeManager.Plugins.Linux.Synology;

public enum DsmErrorKind
{
    Other,
    Transport,
    BadCredentials,
    AccountDisabled,
    PermissionDenied,
    TwoFactorRequired,
    IpBlocked,
    PasswordExpired,
    SessionExpired,
}

/// <summary>A DSM Web API call failed — either DSM answered <c>success:false</c> with
/// an error code, or the call could not be completed (<see cref="DsmErrorKind.Transport"/>).</summary>
public sealed class DsmApiException : Exception
{
    public DsmApiException(int code, string api)
        : base($"DSM API {api} failed with error code {code}{Meaning(code)}")
    {
        Code = code;
        Kind = Classify(code);
    }

    public DsmApiException(string message, Exception? inner = null)
        : base(message, inner)
    {
        Kind = DsmErrorKind.Transport;
    }

    /// <summary>DSM's numeric error code; 0 for transport failures.</summary>
    public int Code { get; }

    public DsmErrorKind Kind { get; }

    // Common Web API codes, and the certificate import codes acme.sh and the
    // Synology Terraform provider document.
    private static string Meaning(int code) => code switch
    {
        105 => " (not a DSM administrator)",
        108 => " (DSM could not read the uploaded certificate files)",
        5510 => " (DSM rejected the certificate)",
        5511 => " (DSM rejected the private key)",
        5512 => " (DSM rejected the intermediate certificate)",
        5514 => " (the private key does not match the certificate)",
        5517 => " (DSM could not verify the certificate chain)",
        5534 => " (DSM requires a private key larger than 1024 bits)",
        _ => "",
    };

    // Codes from Synology's DSM Login Web API Guide (400-410) and the common
    // Web API error table (105 no permission; 106 session timeout, 107 session
    // interrupted by a duplicate login, 119 invalid session).
    private static DsmErrorKind Classify(int code) => code switch
    {
        400 => DsmErrorKind.BadCredentials,
        401 => DsmErrorKind.AccountDisabled,
        402 or 105 => DsmErrorKind.PermissionDenied,
        403 or 404 or 406 => DsmErrorKind.TwoFactorRequired,
        407 => DsmErrorKind.IpBlocked,
        408 or 409 or 410 => DsmErrorKind.PasswordExpired,
        106 or 107 or 119 => DsmErrorKind.SessionExpired,
        _ => DsmErrorKind.Other,
    };
}
