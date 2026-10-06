using System.Net;
using System.Net.Http;

using AcmeManager.Plugins.Linux.Synology;

namespace AcmeManager.Tests.Unit;

public sealed class DsmApiClientTests
{
    private const string AuthInfo =
        """{"data":{"SYNO.API.Auth":{"path":"entry.cgi","minVersion":1,"maxVersion":7}},"success":true}""";

    private const string LoginOk =
        """{"data":{"did":"d1","is_portal_port":false,"sid":"SID123","synotoken":"TOK456"},"success":true}""";

    internal sealed class StubHandler : HttpMessageHandler
    {
        public List<(HttpMethod Method, Uri Uri, string? Body, string? Token)> Requests { get; } = new();
        public Queue<HttpResponseMessage> Responses { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
        {
            var body = req.Content is null ? null : await req.Content.ReadAsStringAsync(ct);
            var token = req.Headers.TryGetValues("X-SYNO-TOKEN", out var v) ? v.Single() : null;
            Requests.Add((req.Method, req.RequestUri!, body, token));
            return Responses.TryDequeue(out var resp)
                ? resp
                : throw new InvalidOperationException($"No queued response for {req.Method} {req.RequestUri}");
        }

        public StubHandler Json(string json, HttpStatusCode status = HttpStatusCode.OK)
        {
            Responses.Enqueue(new HttpResponseMessage(status)
            {
                Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json"),
            });
            return this;
        }

        public StubHandler Redirect(string location)
        {
            var resp = new HttpResponseMessage(HttpStatusCode.Found);
            resp.Headers.Location = new Uri(location);
            Responses.Enqueue(resp);
            return this;
        }
    }

    private static DsmApiClient Client(StubHandler handler, string baseUrl = "http://127.0.0.1:5000") =>
        new(new Uri(baseUrl), new HttpClient(handler), ownsHttp: true);

    [Fact]
    public async Task Login_PostsCredentialsInBody_AndReturnsSession()
    {
        var handler = new StubHandler().Json(AuthInfo).Json(LoginOk);
        using var client = Client(handler);

        var session = await client.LoginAsync(@"EXAMPLE\admin", "p@ss&word", CancellationToken.None);

        Assert.Equal("SID123", session.Sid);
        Assert.Equal("TOK456", session.SynoToken);
        Assert.Equal(7, session.AuthVersion);
        var login = handler.Requests[1];
        Assert.Equal(HttpMethod.Post, login.Method);
        Assert.Equal("/webapi/entry.cgi", login.Uri.AbsolutePath);
        Assert.DoesNotContain("passwd", login.Uri.Query);
        Assert.Contains("account=EXAMPLE%5Cadmin", login.Body);
        Assert.Contains("passwd=p%40ss%26word", login.Body);
        Assert.Contains("enable_syno_token=yes", login.Body);
    }

    [Theory]
    [InlineData(400, DsmErrorKind.BadCredentials)]
    [InlineData(401, DsmErrorKind.AccountDisabled)]
    [InlineData(402, DsmErrorKind.PermissionDenied)]
    [InlineData(403, DsmErrorKind.TwoFactorRequired)]
    [InlineData(406, DsmErrorKind.TwoFactorRequired)]
    [InlineData(407, DsmErrorKind.IpBlocked)]
    [InlineData(105, DsmErrorKind.PermissionDenied)]
    [InlineData(999, DsmErrorKind.Other)]
    public async Task Login_Failure_ThrowsWithClassifiedCode(int code, DsmErrorKind kind)
    {
        var handler = new StubHandler().Json(AuthInfo).Json($$"""{"error":{"code":{{code}}},"success":false}""");
        using var client = Client(handler);

        var ex = await Assert.ThrowsAsync<DsmApiException>(
            () => client.LoginAsync("u", "p", CancellationToken.None));

        Assert.Equal(code, ex.Code);
        Assert.Equal(kind, ex.Kind);
    }

    [Fact]
    public async Task Login_FollowsHttpsRedirect_ForSubsequentCalls()
    {
        var handler = new StubHandler()
            .Redirect("https://127.0.0.1:5001/webapi/query.cgi")
            .Json(AuthInfo)
            .Json(LoginOk);
        using var client = Client(handler);

        await client.LoginAsync("u", "p", CancellationToken.None);

        Assert.Equal("https://127.0.0.1:5001/", client.BaseAddress.ToString());
        Assert.Equal("https", handler.Requests[2].Uri.Scheme);
        Assert.Equal(5001, handler.Requests[2].Uri.Port);
    }

    [Fact]
    public async Task Redirect_ToAnotherHost_IsRefused()
    {
        var handler = new StubHandler().Redirect("https://evil.example.com/webapi/query.cgi");
        using var client = Client(handler);

        await Assert.ThrowsAsync<DsmApiException>(() => client.LoginAsync("u", "p", CancellationToken.None));
    }

    [Fact]
    public async Task ListCertificates_SendsSessionAndToken_AndParsesServices()
    {
        var handler = new StubHandler().Json(AuthInfo).Json(LoginOk).Json("""
            {"success":true,"data":{"certificates":[
              {"id":"abc","desc":"Certadel nas","is_default":true,
               "subject":{"common_name":"nas.ad.example.com","sub_alt_name":["nas.ad.example.com"]},
               "valid_till":"Jan 30 23:59:59 2027 GMT",
               "services":[{"display_name":"DSM Desktop Service","service":"default","subscriber":"system","isPkg":false},
                           {"display_name":"nas.example.com","service":"uuid-1","subscriber":"ReverseProxy","isPkg":false}]},
              {"id":"def","desc":"","is_default":"false","subject":{"common_name":"synology"},"services":[]}]}}
            """);
        using var client = Client(handler);
        var session = await client.LoginAsync("u", "p", CancellationToken.None);

        var certs = await client.ListCertificatesAsync(session, CancellationToken.None);

        var call = handler.Requests[2];
        Assert.Equal("TOK456", call.Token);
        Assert.Contains("api=SYNO.Core.Certificate.CRT", call.Body);
        Assert.Contains("_sid=SID123", call.Body);
        Assert.Equal(2, certs.Count);
        Assert.True(certs[0].IsDefault);
        Assert.False(certs[1].IsDefault);
        Assert.Equal("nas.ad.example.com", certs[0].CommonName);
        Assert.Equal(new DateTimeOffset(2027, 1, 30, 23, 59, 59, TimeSpan.Zero), certs[0].ValidTill);
        Assert.Equal(["DSM Desktop Service", "nas.example.com"], certs[0].Services.Select(s => s.DisplayName));
        Assert.Equal("ReverseProxy", certs[0].Services[1].Subscriber);
        Assert.Contains("\"service\":\"uuid-1\"", certs[0].Services[1].RawJson);
    }

    [Fact]
    public async Task Logout_IsBestEffort()
    {
        var handler = new StubHandler().Json(AuthInfo).Json(LoginOk).Json("oops", HttpStatusCode.InternalServerError);
        using var client = Client(handler);
        var session = await client.LoginAsync("u", "p", CancellationToken.None);

        await client.LogoutAsync(session, CancellationToken.None);

        Assert.Contains("method=logout", handler.Requests[2].Body);
    }

    [Theory]
    [InlineData("https://127.0.0.1:5443/webapi/query.cgi")] // not DSM's HTTPS port
    [InlineData("http://127.0.0.1:5001/webapi/query.cgi")]  // not HTTPS
    public async Task Redirect_ToUnexpectedPortOrScheme_IsRefused(string location)
    {
        var handler = new StubHandler().Redirect(location);
        using var client = Client(handler);

        await Assert.ThrowsAsync<DsmApiException>(() => client.LoginAsync("u", "p", CancellationToken.None));
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("""{"success":true,"data":[]}""")]
    [InlineData("""{"success":false,"error":"nope"}""")]
    [InlineData("""{"success":true,"data":{"sid":{"nested":1}}}""")]
    public async Task OddLoginResponses_SurfaceAsDsmApiException(string loginJson)
    {
        var handler = new StubHandler().Json(AuthInfo).Json(loginJson);
        using var client = Client(handler);

        await Assert.ThrowsAsync<DsmApiException>(() => client.LoginAsync("u", "p", CancellationToken.None));
    }

    [Fact]
    public async Task OddCertificateEntries_AreTolerated()
    {
        var handler = new StubHandler().Json(AuthInfo).Json(LoginOk).Json("""
            {"success":true,"data":{"certificates":["junk",{"id":"a","subject":"x","services":[1,{"display_name":"d"}]}]}}
            """);
        using var client = Client(handler);
        var session = await client.LoginAsync("u", "p", CancellationToken.None);

        var certs = await client.ListCertificatesAsync(session, CancellationToken.None);

        var cert = Assert.Single(certs);
        Assert.Null(cert.CommonName);
        Assert.Equal("d", Assert.Single(cert.Services).DisplayName);
    }

    [Theory]
    [InlineData("http://127.0.0.1:5000", "http://127.0.0.1:5000/")]
    [InlineData("https://127.0.0.1:5001/some/path", "https://127.0.0.1:5001/")]
    [InlineData("https://nas.ad.example.com:5001", "https://nas.ad.example.com:5001/")]
    public void ValidateEndpoint_AcceptsAndNormalizes(string url, string expected) =>
        Assert.Equal(expected, DsmApiClient.ValidateEndpoint(new Uri(url)).ToString());

    [Theory]
    [InlineData("http://nas.ad.example.com:5000")]   // clear-text password off-box
    [InlineData("ftp://127.0.0.1")]
    [InlineData("https://admin:pw@127.0.0.1:5001")]
    [InlineData("http://127.0.0.1:5000/?x=1")]
    public void ValidateEndpoint_RejectsUnsafeEndpoints(string url) =>
        Assert.Throws<ArgumentException>(() => DsmApiClient.ValidateEndpoint(new Uri(url)));

    [Theory]
    [InlineData("http://127.0.0.1:5000", true)]
    [InlineData("https://localhost:5001", true)]
    [InlineData("https://[::1]:5001", true)]
    [InlineData("https://nas.ad.example.com:5001", false)]
    public void LoopbackDetection(string url, bool expected) =>
        Assert.Equal(expected, DsmApiClient.IsLoopback(new Uri(url)));
}
