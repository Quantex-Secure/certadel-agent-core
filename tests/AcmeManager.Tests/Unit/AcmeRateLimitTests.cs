using AcmeManager.Core.Acme;

namespace AcmeManager.Tests.Unit;

public sealed class AcmeRateLimitTests
{
    // The exact shape Let's Encrypt / Certes surfaces.
    private const string RateLimitMessage =
        "Fail to load resource from 'https://acme-v02.api.letsencrypt.org/acme/new-order'. " +
        "urn:ietf:params:acme:error:rateLimited: too many certificates (5) already issued for this " +
        "exact set of identifiers in the last 168h0m0s, retry after 2026-06-11 11:37:27 UTC: see " +
        "https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers";

    [Fact]
    public void TryGetRetryAfter_ParsesTheUtcTimestamp()
    {
        var ok = AcmeRateLimit.TryGetRetryAfter(new Exception(RateLimitMessage), out var retryAfter);

        Assert.True(ok);
        Assert.Equal(new DateTimeOffset(2026, 6, 11, 11, 37, 27, TimeSpan.Zero), retryAfter);
        Assert.Equal(TimeSpan.Zero, retryAfter.Offset); // parsed as UTC
    }

    [Fact]
    public void IsRateLimited_TrueForRateLimitError_FalseOtherwise()
    {
        Assert.True(AcmeRateLimit.IsRateLimited(new Exception(RateLimitMessage)));
        Assert.False(AcmeRateLimit.IsRateLimited(new Exception("connection refused")));
    }

    [Fact]
    public void TryGetRetryAfter_FindsItInAnInnerException()
    {
        var wrapped = new InvalidOperationException("renewal failed", new Exception(RateLimitMessage));

        Assert.True(AcmeRateLimit.TryGetRetryAfter(wrapped, out var retryAfter));
        Assert.Equal(2026, retryAfter.Year);
    }

    [Fact]
    public void TryGetRetryAfter_FalseWhenNoTimestamp()
    {
        // Rate-limited but without a parseable "retry after" — still no crash, just false.
        Assert.False(AcmeRateLimit.TryGetRetryAfter(
            new Exception("urn:ietf:params:acme:error:rateLimited: too many requests"), out _));
    }
}