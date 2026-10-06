namespace AcmeManager.Api.Contracts;

/// <summary>
/// Safe, client-facing error envelope returned by the management API. Carries a
/// stable machine code and a human message only — never stack traces, SQL, or
/// filesystem paths.
/// </summary>
public sealed record ApiError(string Code, string Message)
{
    public const string NotFound = "not_found";
    public const string Conflict = "conflict";
    public const string Invalid = "invalid_request";
    public const string RunFailed = "run_failed";
}