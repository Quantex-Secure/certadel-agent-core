using System.Net.Http;

using AcmeManager.Plugins.Linux.Synology;
using AcmeManager.Service.Authentication;

using Microsoft.Extensions.Logging.Abstractions;

namespace AcmeManager.Tests.Unit;

public sealed class DsmAuthBackendTests
{
    private const string AuthInfo =
        """{"data":{"SYNO.API.Auth":{"path":"entry.cgi","minVersion":1,"maxVersion":7}},"success":true}""";
    private const string LoginOk = """{"data":{"sid":"S","synotoken":"T"},"success":true}""";
    private const string Ok = """{"success":true}""";

    private static DsmAuthBackend Backend(DsmApiClientTests.StubHandler handler, TimeProvider? clock = null) =>
        new(() => new DsmApiClient(new Uri("http://127.0.0.1:5000"), new HttpClient(handler), ownsHttp: true),
            NullLogger<DsmAuthBackend>.Instance,
            clock ?? TimeProvider.System);

    private sealed class ManualClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UnixEpoch;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static DsmApiClientTests.StubHandler AdminSignIn(DsmApiClientTests.StubHandler handler) =>
        handler.Json(AuthInfo).Json(LoginOk).Json("""{"success":true,"data":{"certificates":[]}}""").Json(Ok);

    [Fact]
    public async Task RepeatedAdminSignIn_IsServedFromCache_UntilItExpires()
    {
        var clock = new ManualClock();
        var handler = AdminSignIn(new DsmApiClientTests.StubHandler());
        var backend = Backend(handler, clock);

        await backend.AuthenticateAsync("admin", "pw", CancellationToken.None);
        var cached = await backend.AuthenticateAsync("admin", "pw", CancellationToken.None);

        Assert.True(cached.Success);
        Assert.Equal([DsmAuthBackend.AdministratorsGroup], cached.Groups);
        Assert.Equal(4, handler.Requests.Count); // one DSM round trip only

        clock.Now += DsmAuthBackend.CacheLifetime + TimeSpan.FromSeconds(1);
        AdminSignIn(handler);
        await backend.AuthenticateAsync("admin", "pw", CancellationToken.None);
        Assert.Equal(8, handler.Requests.Count);
    }

    [Fact]
    public async Task Cache_DoesNotMatch_ADifferentPassword()
    {
        var handler = AdminSignIn(new DsmApiClientTests.StubHandler());
        var backend = Backend(handler);
        await backend.AuthenticateAsync("admin", "pw", CancellationToken.None);
        handler.Json(AuthInfo).Json("""{"error":{"code":400},"success":false}""");

        var result = await backend.AuthenticateAsync("admin", "wrong", CancellationToken.None);

        Assert.False(result.Success);
    }

    [Fact]
    public async Task NonAdministrator_IsNotCached()
    {
        var handler = new DsmApiClientTests.StubHandler()
            .Json(AuthInfo).Json(LoginOk).Json("""{"error":{"code":105},"success":false}""").Json(Ok);
        var backend = Backend(handler);
        await backend.AuthenticateAsync("alice", "pw", CancellationToken.None);
        AdminSignIn(handler); // alice was promoted in DSM since

        var result = await backend.AuthenticateAsync("alice", "pw", CancellationToken.None);

        Assert.Equal([DsmAuthBackend.AdministratorsGroup], result.Groups);
    }

    [Fact]
    public async Task Administrator_IsAuthenticated_WithAdministratorsGroup_AndLoggedOut()
    {
        var handler = new DsmApiClientTests.StubHandler()
            .Json(AuthInfo).Json(LoginOk)
            .Json("""{"success":true,"data":{"certificates":[]}}""")
            .Json(Ok);

        var result = await Backend(handler).AuthenticateAsync(@"EXAMPLE\admin", "pw", CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(@"EXAMPLE\admin", result.Username);
        Assert.Equal([DsmAuthBackend.AdministratorsGroup], result.Groups);
        Assert.Contains("method=logout", handler.Requests[^1].Body);
        Assert.True(new AllowedGroupAuthorizer(DsmAuthBackend.AdministratorsGroup).IsAuthorized(result.Groups));
    }

    [Fact]
    public async Task NonAdministrator_IsAuthenticated_WithNoGroups_SoAuthorizationRefuses()
    {
        var handler = new DsmApiClientTests.StubHandler()
            .Json(AuthInfo).Json(LoginOk)
            .Json("""{"error":{"code":105},"success":false}""")
            .Json(Ok);

        var result = await Backend(handler).AuthenticateAsync("alice", "pw", CancellationToken.None);

        Assert.True(result.Success);
        Assert.Empty(result.Groups!);
        Assert.False(new AllowedGroupAuthorizer(DsmAuthBackend.AdministratorsGroup).IsAuthorized(result.Groups));
        Assert.Contains("method=logout", handler.Requests[^1].Body);
    }

    [Theory]
    [InlineData(400, "Invalid username or password")]
    [InlineData(403, "two-factor")]
    [InlineData(407, "blocked")]
    public async Task LoginFailure_IsReportedWithoutSuccess(int code, string reasonFragment)
    {
        var handler = new DsmApiClientTests.StubHandler()
            .Json(AuthInfo)
            .Json($$"""{"error":{"code":{{code}}},"success":false}""");

        var result = await Backend(handler).AuthenticateAsync("u", "pw", CancellationToken.None);

        Assert.False(result.Success);
        Assert.Contains(reasonFragment, result.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DsmUnreachable_FailsClosed()
    {
        var handler = new DsmApiClientTests.StubHandler(); // no responses → throws

        var result = await Backend(handler).AuthenticateAsync("u", "pw", CancellationToken.None);

        Assert.False(result.Success);
    }

    [Fact]
    public async Task BlankCredentials_AreRefusedWithoutCallingDsm()
    {
        var handler = new DsmApiClientTests.StubHandler();

        var result = await Backend(handler).AuthenticateAsync(" ", "", CancellationToken.None);

        Assert.False(result.Success);
        Assert.Empty(handler.Requests);
    }
}

public sealed class DsmPlatformTests
{
    [Fact]
    public void DetectsDsm_FromVersionFile()
    {
        var file = Path.GetTempFileName();
        try
        {
            File.WriteAllText(file, "majorversion=\"7\"\nminorversion=\"4\"\nproductversion=\"7.4.1\"\nbuildnumber=\"90080\"\n");
            var info = DsmPlatform.Read(file);
            Assert.NotNull(info);
            Assert.Equal("7.4.1", info!.ProductVersion);
            Assert.Equal("90080", info.BuildNumber);
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public void MalformedVersionFile_WithDuplicateKeys_DoesNotThrow()
    {
        var file = Path.GetTempFileName();
        try
        {
            File.WriteAllText(file, "productversion=\"7.4.1\"\nproductversion=\"7.4.2\"\n");
            Assert.Equal("7.4.1", DsmPlatform.Read(file)!.ProductVersion);
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public void NonDsm_ReturnsNull()
    {
        Assert.Null(DsmPlatform.Read(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"))));
        var file = Path.GetTempFileName();
        try
        {
            File.WriteAllText(file, "NAME=\"Ubuntu\"\n");
            Assert.Null(DsmPlatform.Read(file));
        }
        finally { File.Delete(file); }
    }
}
