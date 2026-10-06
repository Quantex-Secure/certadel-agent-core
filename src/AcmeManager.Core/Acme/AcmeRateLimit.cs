using System.Globalization;
using System.Text.RegularExpressions;

namespace AcmeManager.Core.Acme;

/// <summary>
/// Recognises ACME "rate limited" errors and extracts the CA's suggested
/// retry-after time, so the scheduler can pause a renewal instead of hammering
/// the limit. Let's Encrypt phrases it as
/// <c>urn:ietf:params:acme:error:rateLimited: … retry after 2026-06-11 11:37:27 UTC</c>.
/// </summary>
public static partial class AcmeRateLimit
{
    [GeneratedRegex(@"retry after\s+(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})\s*UTC",
        RegexOptions.IgnoreCase)]
    private static partial Regex RetryAfterPattern();

    /// <summary>True if the exception (or any inner one) is an ACME rate-limit error.</summary>
    public static bool IsRateLimited(Exception? ex) =>
        Messages(ex).Any(m =>
            m.Contains("ratelimited", StringComparison.OrdinalIgnoreCase)
            || m.Contains("rate limit", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Extracts the CA's "retry after" time (as UTC) from a rate-limit error, if present.
    /// </summary>
    public static bool TryGetRetryAfter(Exception? ex, out DateTimeOffset retryAfterUtc)
    {
        foreach (var message in Messages(ex))
        {
            var match = RetryAfterPattern().Match(message);
            if (match.Success
                && DateTimeOffset.TryParse(
                    $"{match.Groups[1].Value}T{match.Groups[2].Value}Z",
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out var parsed))
            {
                retryAfterUtc = parsed;
                return true;
            }
        }
        retryAfterUtc = default;
        return false;
    }

    private static IEnumerable<string> Messages(Exception? ex)
    {
        for (; ex is not null; ex = ex.InnerException)
        {
            yield return ex.Message;
        }
    }
}