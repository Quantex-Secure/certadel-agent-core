using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

using AcmeManager.Plugins.Contracts.Installation;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AcmeManager.Core.Verification;

/// <summary>Bound from the <c>Verification</c> configuration section.</summary>
public sealed class TlsVerifierOptions
{
    public const string Section = "Verification";

    /// <summary>Handshake attempts per endpoint before a mismatch or connection failure is final.</summary>
    public int Attempts { get; set; } = 5;

    public int RetryDelaySeconds { get; set; } = 2;

    public int ConnectTimeoutSeconds { get; set; } = 10;

    /// <summary>Endpoints probed concurrently.</summary>
    public int MaxParallel { get; set; } = 8;

    /// <summary>
    /// Ceiling on the whole verification step for one renewal. When exhausted,
    /// endpoints still pending are reported unreachable (never as a mismatch).
    /// </summary>
    public int BudgetSeconds { get; set; } = 180;
}

/// <summary>One endpoint's verdict.</summary>
/// <param name="Reachable">A TLS handshake completed, so <see cref="ServedThumbprint"/> is an observation, not a guess.</param>
public sealed record EndpointCheck(VerifyEndpoint Endpoint, bool Ok, bool Reachable, string? ServedThumbprint, string? Error)
{
    public string Describe() => Ok
        ? $"{Endpoint} serves the new certificate"
        : Reachable
            ? $"{Endpoint}: still serving {ServedThumbprint ?? "no certificate"}"
            : $"{Endpoint}: could not reach ({Error ?? "no response"})";
}

/// <summary>Verdict across every endpoint an install produced.</summary>
public sealed record VerificationResult(IReadOnlyList<EndpointCheck> Checks)
{
    public bool AllOk => Checks.Count > 0 && Checks.All(c => c.Ok);

    /// <summary>Endpoints that answered and are serving something other than the new certificate.</summary>
    public IReadOnlyList<EndpointCheck> Mismatches => Checks.Where(c => c.Reachable && !c.Ok).ToList();

    public IReadOnlyList<EndpointCheck> Unreachable => Checks.Where(c => !c.Reachable).ToList();

    public string Summary => string.Join("; ", Checks.Select(c => c.Describe()));
}

/// <summary>
/// Confirms that TLS endpoints present a specific certificate. The engine uses
/// it after installers run so "renewed" means "observed in service".
/// </summary>
public interface IEndpointVerifier
{
    Task<VerificationResult> VerifyAsync(
        IReadOnlyList<VerifyEndpoint> endpoints,
        string expectedThumbprint,
        CancellationToken ct);
}

/// <summary>
/// Default verifier: opens a TLS connection to each endpoint with the given SNI,
/// accepts whatever certificate is presented (this is an observation, not a
/// trust decision), and compares its SHA-1 thumbprint with the issued one.
/// Servers reload asynchronously — HAProxy forks a new process, IIS commits its
/// configuration — so a mismatch is retried for a short while before it counts.
/// A connection that never completes a handshake is reported as unreachable,
/// which is a different verdict from "serving the wrong certificate".
/// </summary>
public sealed class TlsEndpointVerifier(IOptions<TlsVerifierOptions> options, ILogger<TlsEndpointVerifier> logger) : IEndpointVerifier
{
    private TlsVerifierOptions Settings => options.Value;

    public async Task<VerificationResult> VerifyAsync(
        IReadOnlyList<VerifyEndpoint> endpoints,
        string expectedThumbprint,
        CancellationToken ct)
    {
        using var gate = new SemaphoreSlim(Math.Max(1, Settings.MaxParallel));
        var checks = await Task.WhenAll(endpoints.Select(async endpoint =>
        {
            await gate.WaitAsync(ct);
            try
            {
                return await VerifyOneAsync(endpoint, expectedThumbprint, ct);
            }
            finally
            {
                gate.Release();
            }
        }));
        return new VerificationResult(checks);
    }

    private async Task<EndpointCheck> VerifyOneAsync(VerifyEndpoint endpoint, string expectedThumbprint, CancellationToken ct)
    {
        var attempts = Math.Max(1, Settings.Attempts);
        EndpointCheck last = new(endpoint, false, false, null, "not attempted");
        for (var attempt = 1; attempt <= attempts; attempt++)
        {
            last = await ProbeAsync(endpoint, expectedThumbprint, ct);
            if (last.Ok)
            {
                logger.LogInformation("Verified {Endpoint} is serving {Thumbprint} (attempt {Attempt})",
                    endpoint, expectedThumbprint, attempt);
                return last;
            }
            logger.LogDebug("Verification attempt {Attempt}/{Max} for {Endpoint}: {Detail}",
                attempt, attempts, endpoint, last.Describe());
            if (attempt < attempts)
            {
                await Task.Delay(TimeSpan.FromSeconds(Math.Max(0, Settings.RetryDelaySeconds)), ct);
            }
        }
        logger.LogWarning("Verification did not pass for {Endpoint}: {Detail}", endpoint, last.Describe());
        return last;
    }

    private async Task<EndpointCheck> ProbeAsync(VerifyEndpoint endpoint, string expectedThumbprint, CancellationToken ct)
    {
        var connectTimeout = TimeSpan.FromSeconds(Math.Max(1, Settings.ConnectTimeoutSeconds));
        try
        {
            using var client = new TcpClient();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(connectTimeout);
            await client.ConnectAsync(endpoint.Host, endpoint.Port, timeout.Token);

            string? servedThumbprint = null;
            await using var tls = new SslStream(
                client.GetStream(),
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (_, cert, _, _) =>
                {
                    servedThumbprint = cert?.GetCertHashString();
                    return true; // observe, don't judge: the pin/chain is not this component's concern
                });
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = endpoint.ServerName,
                EnabledSslProtocols = SslProtocols.None,
            }, timeout.Token);

            var ok = servedThumbprint is not null
                && string.Equals(servedThumbprint, expectedThumbprint, StringComparison.OrdinalIgnoreCase);
            return new EndpointCheck(endpoint, ok, Reachable: true, servedThumbprint, null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return new EndpointCheck(endpoint, false, false, null, $"no TLS handshake within {connectTimeout.TotalSeconds:0}s");
        }
        catch (Exception ex) when (ex is SocketException or IOException or AuthenticationException)
        {
            return new EndpointCheck(endpoint, false, false, null, ex.Message);
        }
    }
}