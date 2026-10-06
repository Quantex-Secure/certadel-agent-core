using AcmeManager.Core.Engine;

namespace AcmeManager.Tests.Unit;

public sealed class MaintenanceWindowTests
{
    private static MaintenanceWindow Weekend() =>
        MaintenanceWindow.Parse("""{"days":["saturday","sunday"],"start":"01:00","end":"05:00","timeZone":"UTC"}""")!;

    // 2026-09-05 is a Saturday.
    private static DateTimeOffset Utc(int day, int hour, int minute = 0) => new(2026, 9, day, hour, minute, 0, TimeSpan.Zero);

    [Fact]
    public void Parse_BlankIsNoWindow()
    {
        Assert.Null(MaintenanceWindow.Parse(null));
        Assert.Null(MaintenanceWindow.Parse("  "));
    }

    [Theory]
    [InlineData("""{"days":[],"start":"01:00","end":"05:00"}""")]
    [InlineData("""{"days":["funday"],"start":"01:00","end":"05:00"}""")]
    [InlineData("""{"days":["monday"],"start":"1am","end":"05:00"}""")]
    [InlineData("""{"days":["monday"],"start":"02:00","end":"02:00"}""")]
    [InlineData("""{"days":["monday"],"start":"02:00","end":"03:00","timeZone":"Mars/Olympus"}""")]
    [InlineData("not json")]
    public void Parse_RejectsUnusableWindows(string json)
    {
        Assert.Throws<FormatException>(() => MaintenanceWindow.Parse(json));
    }

    [Fact]
    public void Parse_RoundTripsThroughToJson()
    {
        var window = Weekend();
        var again = MaintenanceWindow.Parse(window.ToJson());
        Assert.Equal(window, again);
        Assert.Equal("Sun, Sat 01:00–05:00 (UTC)", window.Describe());
    }

    [Fact]
    public void Contains_InsideAndOutside()
    {
        var window = Weekend();
        Assert.True(window.Contains(Utc(5, 1)));        // Sat 01:00
        Assert.True(window.Contains(Utc(5, 4, 59)));    // Sat 04:59
        Assert.False(window.Contains(Utc(5, 5)));       // Sat 05:00 (end is exclusive)
        Assert.False(window.Contains(Utc(5, 0, 59)));   // Sat 00:59
        Assert.False(window.Contains(Utc(4, 2)));       // Fri 02:00: not a window day
        Assert.True(window.Contains(Utc(6, 3)));        // Sun 03:00
    }

    [Fact]
    public void Contains_OvernightRange_BelongsToTheDayItStarted()
    {
        var window = MaintenanceWindow.Parse("""{"days":["saturday"],"start":"22:00","end":"02:00","timeZone":"UTC"}""")!;
        Assert.True(window.Contains(Utc(5, 23)));        // Sat 23:00
        Assert.True(window.Contains(Utc(6, 1)));         // Sun 01:00: still Saturday's window
        Assert.False(window.Contains(Utc(6, 2)));        // Sun 02:00: over
        Assert.False(window.Contains(Utc(6, 23)));       // Sun 23:00: Sunday isn't a window day
    }

    [Fact]
    public void Contains_HonoursTheTimeZone()
    {
        // 01:00–05:00 in Tokyo (UTC+9) is 16:00–20:00 UTC the previous day.
        var window = MaintenanceWindow.Parse("""{"days":["saturday"],"start":"01:00","end":"05:00","timeZone":"Asia/Tokyo"}""")!;
        Assert.True(window.Contains(Utc(4, 17)));   // Fri 17:00 UTC = Sat 02:00 Tokyo
        Assert.False(window.Contains(Utc(5, 2)));   // Sat 02:00 UTC = Sat 11:00 Tokyo
    }

    [Fact]
    public void DueCalculator_HoldsADueRenewal_UntilTheWindowOpens()
    {
        var window = Weekend();
        var facts = new RenewalScheduleFacts(
            Enabled: true, RenewalWindowDays: 30,
            LastAttemptAt: Utc(1, 0).AddDays(-70), LastSuccessAt: Utc(1, 0).AddDays(-70),
            RetryAfter: null, ConsecutiveFailures: 0,
            LatestNotBefore: Utc(1, 0).AddDays(-70), LatestNotAfter: Utc(1, 0).AddDays(20),
            Window: window);

        var weekday = RenewalDueCalculator.Evaluate(facts, Utc(3, 2)); // Thu 02:00
        var saturday = RenewalDueCalculator.Evaluate(facts, Utc(5, 2)); // Sat 02:00

        Assert.False(weekday.IsDue);
        Assert.Contains("maintenance window", weekday.Reason);
        Assert.True(saturday.IsDue);
    }

    [Fact]
    public void DueCalculator_OverridesTheWindow_WhenExpiryIsDaysAway()
    {
        var facts = new RenewalScheduleFacts(
            Enabled: true, RenewalWindowDays: 30,
            LastAttemptAt: Utc(1, 0).AddDays(-88), LastSuccessAt: Utc(1, 0).AddDays(-88),
            RetryAfter: null, ConsecutiveFailures: 0,
            LatestNotBefore: Utc(1, 0).AddDays(-88), LatestNotAfter: Utc(3, 2).AddDays(2),
            Window: Weekend());

        var decision = RenewalDueCalculator.Evaluate(facts, Utc(3, 2)); // Thu, outside the window, 2 days to expiry

        Assert.True(decision.IsDue);
        Assert.Contains("overridden", decision.Reason);
    }

    [Fact]
    public void DueCalculator_NeverIssued_StillWaitsForTheWindow()
    {
        var facts = new RenewalScheduleFacts(true, 30, null, null, null, 0, null, null, Weekend());
        Assert.False(RenewalDueCalculator.Evaluate(facts, Utc(3, 2)).IsDue);
        Assert.True(RenewalDueCalculator.Evaluate(facts, Utc(5, 2)).IsDue);
    }
}