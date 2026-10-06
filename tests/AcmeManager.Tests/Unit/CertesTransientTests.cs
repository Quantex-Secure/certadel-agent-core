using AcmeManager.Core.Acme;

namespace AcmeManager.Tests.Unit;

public sealed class CertesTransientTests
{
    [Theory]
    [InlineData("Service busy; retry later.", true)]
    [InlineData("urn:ietf:params:acme:error:rateLimited: Service busy; retry later.", true)]
    [InlineData("The operation has timed out.", true)]
    [InlineData("Service is temporarily unavailable", true)]
    [InlineData("unauthorized: account does not exist", false)]
    [InlineData("rejected: bad CSR", false)]
    public void IsTransient_ClassifiesByMessage(string message, bool expected) =>
        Assert.Equal(expected, CertesAcmeClient.IsTransient(new Exception(message)));

    [Fact]
    public void IsTransient_HardRateLimitWithRetryAfter_IsNotTransient()
    {
        // A real "too many certificates" limit carries a retry-after timestamp and
        // must pause (not retry) — IsTransient must say false so the pause logic runs.
        var hardLimit = new Exception(
            "urn:ietf:params:acme:error:rateLimited: too many certificates (5) already issued " +
            "for this exact set of identifiers in the last 168h0m0s, retry after 2026-06-11 11:37:27 UTC");

        Assert.False(CertesAcmeClient.IsTransient(hardLimit));
    }

    [Fact]
    public void IsTransient_NetworkExceptions_AreTransient()
    {
        Assert.True(CertesAcmeClient.IsTransient(new HttpRequestException("connection reset")));
        Assert.True(CertesAcmeClient.IsTransient(new TaskCanceledException("request timed out")));
    }
}