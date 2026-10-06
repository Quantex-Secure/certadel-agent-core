using System.Net;
using System.Text;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Validation;

using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.BuiltIn.Validation;

public sealed record SelfHostedHttp01Options : PluginOptions
{
    /// <summary>Port to bind for the challenge listener. ACME spec requires :80 unless redirected.</summary>
    public int Port { get; init; } = 80;

    /// <summary>Bind address — "+" for all interfaces, "127.0.0.1" for loopback, etc.</summary>
    public string ListenAddress { get; init; } = "+";
}

/// <summary>
/// HTTP-01 validator that binds an <see cref="HttpListener"/> on the challenge
/// port for the duration of validation. Only viable when no other web server
/// holds port 80; on Windows requires either Administrator or a netsh ACL.
///
/// Not safe for concurrent use — one instance handles one validation at a
/// time. Since OrderRunner authorizes identifiers serially this is sufficient
/// for v1; concurrent renewals targeting the same port would need orchestration.
/// </summary>
public sealed class SelfHostedHttp01Validator(ILogger<SelfHostedHttp01Validator> logger) : IValidator
{
    private HttpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _serveTask;

    public PluginMetadata Metadata { get; } = new(
        Id: "validation.http-01.selfhosted",
        Name: "HTTP-01 (self-hosted)",
        Description: "Binds an HTTP listener on the challenge port to serve the token directly.",
        Category: PluginCategory.Validation,
        Version: new Version(1, 0, 0));

    public ChallengeType ChallengeType => ChallengeType.Http01;

    public ValueTask PrepareAsync(ValidationContext ctx, CancellationToken ct)
    {
        var opts = (SelfHostedHttp01Options)ctx.Options;

        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://{opts.ListenAddress}:{opts.Port}/.well-known/acme-challenge/");
        _listener.Start();

        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = ctx.Token;
        var keyAuth = ctx.KeyAuthorization;

        _serveTask = Task.Run(() => ServeAsync(_listener, token, keyAuth, _cts.Token));
        logger.LogInformation(
            "Self-hosted HTTP-01 listening on {Address}:{Port} for token {Token}",
            opts.ListenAddress, opts.Port, token);

        return ValueTask.CompletedTask;
    }

    public async ValueTask CleanupAsync(ValidationContext ctx, CancellationToken ct)
    {
        try { _cts?.Cancel(); }
        catch (Exception ex) { logger.LogDebug(ex, "Self-hosted HTTP-01: cancelling the serve loop failed."); }
        try { _listener?.Stop(); }
        catch (Exception ex) { logger.LogDebug(ex, "Self-hosted HTTP-01: stopping the listener failed."); }
        try { _listener?.Close(); }
        catch (Exception ex) { logger.LogDebug(ex, "Self-hosted HTTP-01: closing the listener failed."); }

        // Await the serve loop's exit with a bounded timeout instead of blocking the
        // thread with .Wait() — this runs inside OrderRunner's async renewal chain.
        if (_serveTask is { } serveTask)
        {
            try
            {
                await serveTask.WaitAsync(TimeSpan.FromSeconds(2));
            }
            catch (TimeoutException)
            {
                logger.LogDebug("Self-hosted HTTP-01: serve loop didn't stop within 2s; abandoning it.");
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "Self-hosted HTTP-01: serve loop faulted during shutdown.");
            }
        }

        _listener = null;
        _cts?.Dispose();
        _cts = null;
        _serveTask = null;
    }

    private static async Task ServeAsync(HttpListener listener, string token, string keyAuth, CancellationToken ct)
    {
        var payload = Encoding.UTF8.GetBytes(keyAuth);
        while (!ct.IsCancellationRequested && listener.IsListening)
        {
            HttpListenerContext context;
            try
            {
                context = await listener.GetContextAsync().WaitAsync(ct);
            }
            catch (OperationCanceledException) { return; }
            catch (HttpListenerException) { return; }
            catch (ObjectDisposedException) { return; }

            try
            {
                var path = context.Request.Url?.AbsolutePath ?? "";
                if (path.EndsWith("/" + token, StringComparison.Ordinal))
                {
                    context.Response.ContentType = "application/octet-stream";
                    context.Response.ContentLength64 = payload.Length;
                    await context.Response.OutputStream.WriteAsync(payload, ct);
                }
                else
                {
                    context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                }
            }
            finally
            {
                context.Response.Close();
            }
        }
    }
}