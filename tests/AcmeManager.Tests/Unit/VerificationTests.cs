using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AcmeManager.Core.Verification;
using AcmeManager.Plugins.Contracts.Installation;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AcmeManager.Tests.Unit;

/// <summary>
/// Phase 1 verification: the TLS probe against an in-process server, the
/// verify-or-rollback runner with fakes, and endpoint option parsing.
/// </summary>
public sealed class VerificationTests
{
    // ---------------- in-process TLS server ----------------

    private static X509Certificate2 SelfSigned(string cn)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={cn}", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(cn);
        request.CertificateExtensions.Add(san.Build());
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        // Re-import as PKCS#12 with a (user-profile) key container: SChannel can't
        // serve TLS from an ephemeral key, so an in-process server needs a real one.
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);
    }

    /// <summary>Serves one certificate per SNI name; falls back to the first for unknown names.</summary>
    private sealed class TlsServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly Dictionary<string, X509Certificate2> _bySni;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _accept;

        public int Port { get; }

        public TlsServer(Dictionary<string, X509Certificate2> bySni)
        {
            _bySni = bySni;
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _accept = AcceptLoopAsync();
        }

        private async Task AcceptLoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(_cts.Token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                _ = HandleAsync(client);
            }
        }

        private async Task HandleAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    await using var tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificateSelectionCallback = (_, sni) =>
                            sni is not null && _bySni.TryGetValue(sni, out var c) ? c : _bySni.Values.First(),
                        ClientCertificateRequired = false,
                    }, _cts.Token);
                }
                catch (Exception)
                {
                    // Client went away or handshake failed — irrelevant to the test.
                }
            }
        }

        public async ValueTask DisposeAsync()
        {
            _cts.Cancel();
            _listener.Stop();
            try { await _accept; } catch (OperationCanceledException) { }
            _cts.Dispose();
        }
    }

    private static TlsEndpointVerifier FastVerifier() =>
        new(Options.Create(new TlsVerifierOptions { Attempts = 2, RetryDelaySeconds = 0, ConnectTimeoutSeconds = 5 }), NullLogger<TlsEndpointVerifier>.Instance);

    [Fact]
    public async Task Verifier_Passes_WhenTheServerPresentsTheExpectedCertificate()
    {
        using var cert = SelfSigned("web.test");
        await using var server = new TlsServer(new() { ["web.test"] = cert });

        var result = await FastVerifier().VerifyAsync(
            [new VerifyEndpoint("127.0.0.1", server.Port, "web.test")], cert.Thumbprint, default);

        Assert.True(result.AllOk, result.Summary);
        Assert.Equal(cert.Thumbprint, result.Checks[0].ServedThumbprint, ignoreCase: true);
    }

    [Fact]
    public async Task Verifier_Fails_WhenTheServerStillServesTheOldCertificate()
    {
        using var old = SelfSigned("web.test");
        using var issued = SelfSigned("web.test");
        await using var server = new TlsServer(new() { ["web.test"] = old });

        var result = await FastVerifier().VerifyAsync(
            [new VerifyEndpoint("127.0.0.1", server.Port, "web.test")], issued.Thumbprint, default);

        Assert.False(result.AllOk);
        Assert.Equal(old.Thumbprint, result.Checks[0].ServedThumbprint, ignoreCase: true);
        Assert.Contains("still serving", result.Summary);
    }

    [Fact]
    public async Task Verifier_SendsSni_SoNameBasedServersPickTheRightCertificate()
    {
        using var a = SelfSigned("a.test");
        using var b = SelfSigned("b.test");
        await using var server = new TlsServer(new() { ["a.test"] = a, ["b.test"] = b });

        var result = await FastVerifier().VerifyAsync(
            [new VerifyEndpoint("127.0.0.1", server.Port, "b.test")], b.Thumbprint, default);

        Assert.True(result.AllOk, result.Summary);
    }

    [Fact]
    public async Task Verifier_ReportsAConnectionFailure_InsteadOfThrowing()
    {
        var result = await FastVerifier().VerifyAsync(
            [new VerifyEndpoint("127.0.0.1", 1, "nothing.test")], "ABC", default); // port 1: nothing listens

        Assert.False(result.AllOk);
        Assert.False(result.Checks[0].Reachable);
        Assert.NotNull(result.Checks[0].Error);
        Assert.Empty(result.Mismatches);
        Assert.Single(result.Unreachable);
    }

    // ---------------- runner ----------------

    private sealed class FakeVerifier(bool ok, bool reachable = true) : IEndpointVerifier
    {
        public List<VerifyEndpoint> Asked { get; } = [];

        public Task<VerificationResult> VerifyAsync(IReadOnlyList<VerifyEndpoint> endpoints, string expectedThumbprint, CancellationToken ct)
        {
            Asked.AddRange(endpoints);
            return Task.FromResult(new VerificationResult(
                endpoints.Select(e => new EndpointCheck(e, ok, reachable, reachable ? (ok ? expectedThumbprint : "OLD") : null, reachable ? null : "refused")).ToList()));
        }
    }

    private static InstallVerificationRunner Runner(IEndpointVerifier verifier) =>
        new(verifier, Options.Create(new TlsVerifierOptions()), NullLogger<InstallVerificationRunner>.Instance);

    [Fact]
    public async Task Runner_ReportsUnreachable_AndDoesNotRollBack_WhenNothingAnswered()
    {
        // "Can't connect" is not evidence the install went wrong: a VIP-bound HAProxy
        // refusing loopback must not turn every renewal into a rollback.
        var rolledBack = false;
        var result = InstallResult.Ok("haproxy") with
        {
            Endpoints = [new VerifyEndpoint("127.0.0.1", 443, "web.test")],
            Rollback = _ => { rolledBack = true; return ValueTask.CompletedTask; },
        };

        var verdict = await Runner(new FakeVerifier(ok: false, reachable: false)).VerifyOrRollbackAsync([result], "T", default);

        Assert.Equal(VerificationKind.Unreachable, verdict.Kind);
        Assert.Contains("could not reach", verdict.Detail);
        Assert.False(rolledBack);
    }

    [Fact]
    public async Task Runner_ReportsIncompleteRollback_WhenAStepHasNoRollbackOrItThrows()
    {
        var verdict = await Runner(new FakeVerifier(ok: false)).VerifyOrRollbackAsync(
        [
            InstallResult.Ok("a") with { Endpoints = [new VerifyEndpoint("h", 1, "a")], Rollback = _ => ValueTask.CompletedTask },
            InstallResult.Ok("b") with { Endpoints = [new VerifyEndpoint("h", 2, "b")] }, // no rollback available
        ], "T", default);

        Assert.Equal(VerificationKind.FailedAndRolledBack, verdict.Kind);
        Assert.False(verdict.AllRolledBack);
        Assert.Contains("NO ROLLBACK available for b", verdict.Detail);
    }

    [Fact]
    public async Task Runner_Skips_WhenNoInstallerReportedAnEndpoint()
    {
        var verifier = new FakeVerifier(ok: true);
        var verdict = await Runner(verifier).VerifyOrRollbackAsync([InstallResult.Ok("script")], "T", default);

        Assert.Equal(VerificationKind.Skipped, verdict.Kind);
        Assert.Contains("no endpoint", verdict.Detail);
        Assert.Empty(verifier.Asked);
    }

    [Fact]
    public async Task Runner_Skips_WithTheOperatorsReason_WhenVerificationIsOff()
    {
        var verdict = await Runner(new FakeVerifier(ok: true)).VerifyOrRollbackAsync(
            [InstallResult.Ok("iis") with { VerificationSkippedReason = VerificationOptions.SkippedByOperator }], "T", default);

        Assert.Equal(VerificationKind.Skipped, verdict.Kind);
        Assert.Contains("switched off", verdict.Detail);
    }

    [Fact]
    public async Task Runner_Verifies_WhenEveryEndpointServesTheNewCertificate()
    {
        var rolledBack = false;
        var result = InstallResult.Ok("iis") with
        {
            Endpoints = [new VerifyEndpoint("127.0.0.1", 443, "web.test")],
            Rollback = _ => { rolledBack = true; return ValueTask.CompletedTask; },
        };

        var verdict = await Runner(new FakeVerifier(ok: true)).VerifyOrRollbackAsync([result], "T", default);

        Assert.Equal(VerificationKind.Verified, verdict.Kind);
        Assert.False(rolledBack);
    }

    [Fact]
    public async Task Runner_RollsBackEveryStepInReverseOrder_WhenVerificationFails()
    {
        var order = new List<string>();
        InstallResult Step(string name) => InstallResult.Ok(name) with
        {
            Endpoints = [new VerifyEndpoint("127.0.0.1", 443, name)],
            Rollback = _ => { order.Add(name); return ValueTask.CompletedTask; },
        };

        var verdict = await Runner(new FakeVerifier(ok: false)).VerifyOrRollbackAsync(
            [Step("first"), Step("second"), Step("third")], "T", default);

        Assert.Equal(VerificationKind.FailedAndRolledBack, verdict.Kind);
        Assert.True(verdict.AllRolledBack);
        Assert.Equal(["third", "second", "first"], order);
        Assert.Contains("still serving", verdict.Detail);
    }

    [Fact]
    public async Task Runner_KeepsRollingBack_WhenOneRollbackThrows()
    {
        var restored = new List<string>();
        var verdict = await Runner(new FakeVerifier(ok: false)).VerifyOrRollbackAsync(
        [
            InstallResult.Ok("a") with { Endpoints = [new VerifyEndpoint("h", 1, "a")], Rollback = _ => { restored.Add("a"); return ValueTask.CompletedTask; } },
            InstallResult.Ok("b") with { Endpoints = [new VerifyEndpoint("h", 2, "b")], Rollback = _ => throw new IOException("disk") },
            InstallResult.Ok("c") with { Endpoints = [new VerifyEndpoint("h", 3, "c")], Rollback = _ => { restored.Add("c"); return ValueTask.CompletedTask; } },
        ], "T", default);

        Assert.Equal(VerificationKind.FailedAndRolledBack, verdict.Kind);
        Assert.False(verdict.AllRolledBack);
        Assert.Equal(["c", "a"], restored);
        Assert.Contains("ROLLBACK FAILED for b", verdict.Detail);
    }

    // ---------------- options ----------------

    [Fact]
    public void Options_ParseHostPortAndSniForms()
    {
        var parsed = VerificationOptions.Parse("shop.example.com, 10.0.0.5:8443, api.example.com@10.0.0.6:443", 443, "cn.example.com");

        Assert.Equal(new VerifyEndpoint("shop.example.com", 443, "shop.example.com"), parsed[0]);
        Assert.Equal(new VerifyEndpoint("10.0.0.5", 8443, "cn.example.com"), parsed[1]); // an address gets the CN as SNI
        Assert.Equal(new VerifyEndpoint("10.0.0.6", 443, "api.example.com"), parsed[2]);
    }

    [Fact]
    public void Options_RejectBadEntries()
    {
        Assert.Throws<ArgumentException>(() => VerificationOptions.Parse("host:notaport", 443, "cn"));
        Assert.Throws<ArgumentException>(() => VerificationOptions.Parse(":443", 443, "cn"));
    }

    [Fact]
    public void Options_Resolve_PrefersExplicit_ThenDefault_AndNothingWhenSkipped()
    {
        var defaults = new[] { new VerifyEndpoint("127.0.0.1", 443, "cn") };
        Assert.Equal(defaults, VerificationOptions.Resolve(false, "", 443, "cn", defaults));
        Assert.Equal("x.test", VerificationOptions.Resolve(false, "x.test", 443, "cn", defaults)[0].Host);
        Assert.Empty(VerificationOptions.Resolve(true, "x.test", 443, "cn", defaults));
    }
}