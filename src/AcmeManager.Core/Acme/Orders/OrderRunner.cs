using System.Security.Cryptography.X509Certificates;

using AcmeManager.Core.Acme.Csr;
using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Validation;

using Microsoft.Extensions.Logging;

using ContractChallengeType = AcmeManager.Plugins.Contracts.Validation.ChallengeType;

namespace AcmeManager.Core.Acme.Orders;

/// <summary>
/// Runs one ACME order end-to-end: create → authorize each identifier via the
/// supplied validator → finalize with a fresh CSR → poll → download → bundle
/// into a PFX. Polling is bounded; <see cref="OrderRunnerOptions"/> controls
/// the interval/limit. Phase 3 wires this behind the plugin-driven engine.
/// </summary>
public sealed class OrderRunner(IAcmeClient acme, ILogger<OrderRunner> logger)
{
    public async Task<OrderResult> RunAsync(
        AcmeAccount account,
        IReadOnlyList<string> identifiers,
        IValidator validator,
        OrderRunnerOptions? opts = null,
        CancellationToken ct = default)
    {
        opts ??= OrderRunnerOptions.Default;

        var order = await acme.CreateOrderAsync(account, identifiers, ct);
        logger.LogInformation(
            "Created order {Url} for {Identifiers}", order.Url, string.Join(", ", identifiers));

        foreach (var authzUrl in order.AuthorizationUrls)
        {
            await AuthorizeAsync(account, authzUrl, validator, opts, ct);
        }

        for (var attempt = 0; attempt < opts.MaxPolls; attempt++)
        {
            order = await acme.RefreshOrderAsync(account, order, ct);
            if (order.Status == OrderStatus.Ready) break;
            if (order.Status == OrderStatus.Invalid)
            {
                throw new InvalidOperationException($"Order {order.Url} became Invalid before finalization.");
            }
            await Task.Delay(opts.PollInterval, ct);
        }

        if (order.Status != OrderStatus.Ready)
        {
            throw new InvalidOperationException(
                $"Order {order.Url} is {order.Status} after authorizations, expected Ready.");
        }

        var csr = CsrGenerator.Generate(identifiers[0], identifiers, opts.CertificateKeyAlgorithm);

        order = await acme.FinalizeOrderAsync(account, order, csr.CsrDer, ct);
        order = await PollOrderAsync(account, order, opts, ct);

        var pemChain = await acme.DownloadCertificateAsync(account, order, ct);
        var pfx = BuildPfx(pemChain, csr.PrivateKeyPem);

        logger.LogInformation("Order {Url} complete — {Count} identifiers", order.Url, identifiers.Count);

        return new OrderResult(pemChain, csr.PrivateKeyPem, pfx, identifiers);
    }

    private async Task AuthorizeAsync(
        AcmeAccount account,
        Uri authzUrl,
        IValidator validator,
        OrderRunnerOptions opts,
        CancellationToken ct)
    {
        var authz = await acme.GetAuthorizationAsync(account, authzUrl, ct);
        if (authz.Status == AuthorizationStatus.Valid)
        {
            logger.LogDebug("Authorization {Url} already Valid — skipping", authzUrl);
            return;
        }

        var wantedType = AcmeTypeStringFor(validator.ChallengeType);
        var challenge = authz.Challenges.FirstOrDefault(c => c.Type == wantedType)
            ?? throw new InvalidOperationException(
                $"No '{wantedType}' challenge available for {authz.Identifier}; got {string.Join(", ", authz.Challenges.Select(c => c.Type))}");

        var publishedValue = validator.ChallengeType == ContractChallengeType.Dns01
            ? acme.ComputeDnsTxtValue(account, challenge)
            : acme.ComputeKeyAuthorization(account, challenge);

        var publishIdentifier = validator.ChallengeType == ContractChallengeType.Dns01
            ? "_acme-challenge." + authz.Identifier
            : authz.Identifier;

        var ctx = new ValidationContext(publishIdentifier, challenge.Token, publishedValue, opts.ValidatorOptions);

        await validator.PrepareAsync(ctx, ct);
        try
        {
            await acme.SubmitChallengeAsync(account, challenge, ct);
            await PollAuthorizationAsync(account, authzUrl, opts, ct);
        }
        finally
        {
            try
            {
                await validator.CleanupAsync(ctx, ct);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Validator cleanup failed for {Identifier}", authz.Identifier);
            }
        }
    }

    private async Task PollAuthorizationAsync(
        AcmeAccount account,
        Uri authzUrl,
        OrderRunnerOptions opts,
        CancellationToken ct)
    {
        for (var attempt = 0; attempt < opts.MaxPolls; attempt++)
        {
            var authz = await acme.GetAuthorizationAsync(account, authzUrl, ct);
            if (authz.Status == AuthorizationStatus.Valid) return;
            if (authz.Status == AuthorizationStatus.Invalid)
            {
                var detail = authz.Challenges
                    .Select(c => c.Error)
                    .FirstOrDefault(e => !string.IsNullOrWhiteSpace(e));
                throw new InvalidOperationException(
                    $"Authorization for {authz.Identifier} reported Invalid by CA"
                    + (string.IsNullOrWhiteSpace(detail) ? "" : $": {detail}"));
            }
            await Task.Delay(opts.PollInterval, ct);
        }
        throw new TimeoutException($"Authorization {authzUrl} did not become Valid within {opts.MaxPolls * opts.PollInterval.TotalSeconds:N0}s");
    }

    private async Task<AcmeOrder> PollOrderAsync(
        AcmeAccount account,
        AcmeOrder order,
        OrderRunnerOptions opts,
        CancellationToken ct)
    {
        for (var attempt = 0; attempt < opts.MaxPolls; attempt++)
        {
            order = await acme.RefreshOrderAsync(account, order, ct);
            if (order.Status == OrderStatus.Valid) return order;
            if (order.Status == OrderStatus.Invalid)
            {
                throw new InvalidOperationException($"Order {order.Url} reported Invalid by CA");
            }
            await Task.Delay(opts.PollInterval, ct);
        }
        throw new TimeoutException($"Order {order.Url} did not become Valid within {opts.MaxPolls * opts.PollInterval.TotalSeconds:N0}s");
    }

    private static string AcmeTypeStringFor(ContractChallengeType type) => type switch
    {
        ContractChallengeType.Http01 => AcmeChallengeTypes.Http01,
        ContractChallengeType.Dns01 => AcmeChallengeTypes.Dns01,
        ContractChallengeType.TlsAlpn01 => AcmeChallengeTypes.TlsAlpn01,
        _ => throw new ArgumentOutOfRangeException(nameof(type)),
    };

    private static byte[] BuildPfx(string chainPem, string privateKeyPem)
    {
        var blocks = SplitPemCerts(chainPem).ToList();
        if (blocks.Count == 0)
        {
            throw new InvalidOperationException("No certificates found in PEM chain");
        }

        var collection = new X509Certificate2Collection
        {
            X509Certificate2.CreateFromPem(blocks[0], privateKeyPem),
        };

        for (var i = 1; i < blocks.Count; i++)
        {
            collection.Add(X509CertificateLoader.LoadCertificate(
                System.Text.Encoding.ASCII.GetBytes(blocks[i])));
        }

        try
        {
            return collection.Export(X509ContentType.Pfx)
                ?? throw new InvalidOperationException("PFX export returned null");
        }
        finally
        {
            // Release the leaf's private-key handle and the intermediates once exported.
            foreach (var cert in collection)
            {
                cert.Dispose();
            }
        }
    }

    private static IEnumerable<string> SplitPemCerts(string pem)
    {
        const string endMarker = "-----END CERTIFICATE-----";
        var idx = 0;
        while (idx < pem.Length)
        {
            var end = pem.IndexOf(endMarker, idx, StringComparison.Ordinal);
            if (end < 0) yield break;
            var block = pem[idx..(end + endMarker.Length)];
            if (block.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
            {
                yield return block.Trim();
            }
            idx = end + endMarker.Length;
        }
    }
}

public sealed record OrderRunnerOptions
{
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(2);

    public int MaxPolls { get; init; } = 30;

    public AcmeKeyAlgorithm CertificateKeyAlgorithm { get; init; } = AcmeKeyAlgorithm.EcP256;

    public PluginOptions ValidatorOptions { get; init; } = EmptyPluginOptions.Instance;

    public static OrderRunnerOptions Default { get; } = new();
}

internal sealed record EmptyPluginOptions : PluginOptions
{
    public static EmptyPluginOptions Instance { get; } = new();
}