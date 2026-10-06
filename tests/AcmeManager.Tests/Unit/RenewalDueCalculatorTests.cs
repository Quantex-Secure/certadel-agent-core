using AcmeManager.Core.Engine;

namespace AcmeManager.Tests.Unit;

public sealed class RenewalDueCalculatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 1, 12, 0, 0, TimeSpan.Zero);

    private static RenewalScheduleFacts Facts(
        bool enabled = true,
        int windowDays = 30,
        DateTimeOffset? lastAttempt = null,
        DateTimeOffset? lastSuccess = null,
        DateTimeOffset? retryAfter = null,
        int failures = 0,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null) =>
        new(enabled, windowDays, lastAttempt, lastSuccess, retryAfter, failures, notBefore, notAfter);

    [Fact]
    public void Disabled_IsNeverDue()
    {
        var decision = RenewalDueCalculator.Evaluate(Facts(enabled: false), Now);
        Assert.False(decision.IsDue);
    }

    [Fact]
    public void NeverIssued_IsDue()
    {
        var decision = RenewalDueCalculator.Evaluate(Facts(), Now);
        Assert.True(decision.IsDue);
    }

    [Fact]
    public void InsideWindow_IsDue()
    {
        var facts = Facts(lastSuccess: Now.AddDays(-70), notBefore: Now.AddDays(-70), notAfter: Now.AddDays(20));
        Assert.True(RenewalDueCalculator.Evaluate(facts, Now).IsDue);
    }

    [Fact]
    public void OutsideWindow_IsNotDue()
    {
        var facts = Facts(lastSuccess: Now.AddDays(-30), notBefore: Now.AddDays(-30), notAfter: Now.AddDays(60));
        Assert.False(RenewalDueCalculator.Evaluate(facts, Now).IsDue);
    }

    [Fact]
    public void RateLimitPause_IsHonoured()
    {
        var facts = Facts(retryAfter: Now.AddHours(1));
        var decision = RenewalDueCalculator.Evaluate(facts, Now);
        Assert.False(decision.IsDue);
        Assert.Contains("rate limit", decision.Reason);
    }

    [Fact]
    public void ExpiredRateLimitPause_NoLongerBlocks()
    {
        var facts = Facts(retryAfter: Now.AddMinutes(-1));
        Assert.True(RenewalDueCalculator.Evaluate(facts, Now).IsDue);
    }

    [Fact]
    public void WindowWiderThanCertLifetime_DoesNotReorderEveryTick()
    {
        // The bug: a 100-day window on a 90-day cert made a freshly issued cert
        // "due" again on the very next tick, ordering once a minute until the CA
        // rate-limited the domain. A success now imposes a floor.
        var issued = Now.AddMinutes(-1);
        var facts = Facts(
            windowDays: 100,
            lastAttempt: issued, lastSuccess: issued,
            notBefore: issued, notAfter: issued.AddDays(90));

        var decision = RenewalDueCalculator.Evaluate(facts, Now);

        Assert.False(decision.IsDue);
        Assert.Contains("minimum interval after success", decision.Reason);
    }

    [Fact]
    public void SuccessFloor_IsAQuarterOfLifetime_ButAtLeastOneDay()
    {
        Assert.Equal(TimeSpan.FromDays(22.5), RenewalDueCalculator.SuccessFloor(Now, Now.AddDays(90)));
        Assert.Equal(TimeSpan.FromDays(1), RenewalDueCalculator.SuccessFloor(Now, Now.AddDays(2)));
        Assert.Equal(TimeSpan.FromDays(1), RenewalDueCalculator.SuccessFloor(null, null));
    }

    [Fact]
    public void AfterSuccessFloorElapses_WideWindowIsDueAgain()
    {
        var issued = Now.AddDays(-23); // > 90/4 = 22.5 days
        var facts = Facts(
            windowDays: 100,
            lastAttempt: issued, lastSuccess: issued,
            notBefore: issued, notAfter: issued.AddDays(90));

        Assert.True(RenewalDueCalculator.Evaluate(facts, Now).IsDue);
    }

    [Fact]
    public void FirstFailure_BacksOffFifteenMinutes()
    {
        var attempt = Now.AddMinutes(-10);
        var facts = Facts(lastAttempt: attempt, lastSuccess: null, failures: 1);

        Assert.False(RenewalDueCalculator.Evaluate(facts, Now).IsDue);
        Assert.True(RenewalDueCalculator.Evaluate(facts, Now.AddMinutes(6)).IsDue);
    }

    [Theory]
    [InlineData(1, 15)]
    [InlineData(2, 30)]
    [InlineData(3, 60)]
    [InlineData(4, 120)]
    [InlineData(5, 240)]
    [InlineData(6, 360)]
    [InlineData(50, 360)]
    public void RetryInterval_EscalatesAndCaps(int failures, int expectedMinutes)
    {
        Assert.Equal(TimeSpan.FromMinutes(expectedMinutes), RenewalDueCalculator.RetryInterval(failures));
    }

    [Fact]
    public void RepeatedFailures_BackOffLonger()
    {
        var attempt = Now.AddMinutes(-40);
        var afterThree = Facts(lastAttempt: attempt, lastSuccess: null, failures: 3); // 60 min back-off
        var afterOne = Facts(lastAttempt: attempt, lastSuccess: null, failures: 1);   // 15 min back-off

        Assert.False(RenewalDueCalculator.Evaluate(afterThree, Now).IsDue);
        Assert.True(RenewalDueCalculator.Evaluate(afterOne, Now).IsDue);
    }

    [Fact]
    public void FailureAfterEarlierSuccess_StillBacksOff_ThenRetries()
    {
        var success = Now.AddDays(-80);
        var failedAttempt = Now.AddMinutes(-5);
        var facts = Facts(
            lastAttempt: failedAttempt, lastSuccess: success, failures: 1,
            notBefore: success, notAfter: success.AddDays(90)); // 10 days left: inside window

        Assert.False(RenewalDueCalculator.Evaluate(facts, Now).IsDue);
        Assert.True(RenewalDueCalculator.Evaluate(facts, Now.AddMinutes(11)).IsDue);
    }
}