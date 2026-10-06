using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

using AcmeManager.Plugins.BuiltIn.Validation;
using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Validation;

using Microsoft.Extensions.Logging.Abstractions;

namespace AcmeManager.Tests.Unit;

public sealed class CloudflareDns01ValidatorTests
{
    private sealed record CapturedRequest(
        HttpMethod Method,
        Uri RequestUri,
        string? AuthScheme,
        string? AuthParameter,
        string? Body);

    private sealed class StubHandler : HttpMessageHandler
    {
        public List<CapturedRequest> Requests { get; } = new();
        public Queue<HttpResponseMessage> Responses { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
        {
            // Snapshot synchronously — the validator disposes the request via `using` after SendAsync returns.
            string? body = req.Content is null ? null : await req.Content.ReadAsStringAsync(ct);
            Requests.Add(new CapturedRequest(
                Method: req.Method,
                RequestUri: req.RequestUri!,
                AuthScheme: req.Headers.Authorization?.Scheme,
                AuthParameter: req.Headers.Authorization?.Parameter,
                Body: body));

            if (!Responses.TryDequeue(out var resp))
            {
                throw new InvalidOperationException(
                    $"No more queued responses for request {req.Method} {req.RequestUri}");
            }
            return resp;
        }

        public void EnqueueJson(HttpStatusCode status, string json) =>
            Responses.Enqueue(new HttpResponseMessage(status)
            {
                Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json"),
            });
    }

    private sealed class StubSecretResolver(string value) : ISecretResolver
    {
        public Task<string> ResolveAsync(string name, CancellationToken ct) => Task.FromResult(value);
    }

    [Fact]
    public async Task Prepare_WalksZones_CreatesRecord_AndSetsBearerAuth()
    {
        var handler = new StubHandler();
        // Zone lookup: www.example.com → not found, example.com → found
        handler.EnqueueJson(HttpStatusCode.OK, """{"result":[],"success":true}""");
        handler.EnqueueJson(HttpStatusCode.OK, """{"result":[{"id":"zone-xyz"}],"success":true}""");
        // Create record
        handler.EnqueueJson(HttpStatusCode.OK, """{"result":{"id":"record-abc","name":"_acme-challenge.www.example.com"},"success":true}""");

        var http = new HttpClient(handler);
        var validator = new CloudflareDns01Validator(
            new StubSecretResolver("token-secret"),
            NullLogger<CloudflareDns01Validator>.Instance,
            http,
            ownsHttp: true);

        var opts = new CloudflareDns01Options
        {
            ApiTokenSecretName = "cf",
            PropagationDelay = TimeSpan.FromMilliseconds(1),
        };
        var ctx = new ValidationContext(
            Identifier: "_acme-challenge.www.example.com",
            Token: "tok-1",
            KeyAuthorization: "txt-value-here",
            Options: opts);

        await validator.PrepareAsync(ctx, default);

        Assert.Equal(3, handler.Requests.Count);

        // First two: zone walk
        Assert.Equal(HttpMethod.Get, handler.Requests[0].Method);
        Assert.Contains("name=www.example.com", handler.Requests[0].RequestUri.Query);
        Assert.Contains("name=example.com", handler.Requests[1].RequestUri.Query);

        // Third: POST to create
        Assert.Equal(HttpMethod.Post, handler.Requests[2].Method);
        Assert.EndsWith("zones/zone-xyz/dns_records", handler.Requests[2].RequestUri.AbsolutePath);

        // Bearer auth on each request
        foreach (var req in handler.Requests)
        {
            Assert.Equal("Bearer", req.AuthScheme);
            Assert.Equal("token-secret", req.AuthParameter);
        }

        // POST body contains the token name & TXT content
        var body = handler.Requests[2].Body!;
        Assert.Contains("\"_acme-challenge.www.example.com\"", body);
        Assert.Contains("\"txt-value-here\"", body);
        Assert.Contains("\"TXT\"", body);
    }

    [Fact]
    public async Task Cleanup_Deletes_CreatedRecord()
    {
        var handler = new StubHandler();
        // Prepare: zone found immediately on first lookup, then create.
        handler.EnqueueJson(HttpStatusCode.OK, """{"result":[{"id":"z1"}],"success":true}""");
        handler.EnqueueJson(HttpStatusCode.OK, """{"result":{"id":"r1","name":"_acme-challenge.example.com"},"success":true}""");
        // Cleanup: just the DELETE.
        handler.EnqueueJson(HttpStatusCode.OK, """{"result":null,"success":true}""");

        var http = new HttpClient(handler);
        var validator = new CloudflareDns01Validator(
            new StubSecretResolver("t"),
            NullLogger<CloudflareDns01Validator>.Instance,
            http,
            ownsHttp: true);

        var opts = new CloudflareDns01Options
        {
            ApiTokenSecretName = "cf",
            PropagationDelay = TimeSpan.FromMilliseconds(1),
        };
        var ctx = new ValidationContext("_acme-challenge.example.com", "tok-2", "val", opts);

        await validator.PrepareAsync(ctx, default);
        await validator.CleanupAsync(ctx, default);

        var deleteReq = handler.Requests[^1];
        Assert.Equal(HttpMethod.Delete, deleteReq.Method);
        Assert.EndsWith("zones/z1/dns_records/r1", deleteReq.RequestUri.AbsolutePath);
    }

    [Fact]
    public async Task Prepare_ThrowsClearError_WhenNoZoneMatches()
    {
        var handler = new StubHandler();
        // Every zone lookup returns empty.
        for (var i = 0; i < 5; i++)
        {
            handler.EnqueueJson(HttpStatusCode.OK, """{"result":[],"success":true}""");
        }
        var http = new HttpClient(handler);
        var validator = new CloudflareDns01Validator(
            new StubSecretResolver("t"),
            NullLogger<CloudflareDns01Validator>.Instance,
            http,
            ownsHttp: true);

        var opts = new CloudflareDns01Options
        {
            ApiTokenSecretName = "cf",
            PropagationDelay = TimeSpan.Zero,
        };
        var ctx = new ValidationContext(
            Identifier: "_acme-challenge.deep.sub.example.com",
            Token: "t",
            KeyAuthorization: "v",
            Options: opts);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await validator.PrepareAsync(ctx, default));

        Assert.Contains("No Cloudflare zone found", ex.Message);
    }
}