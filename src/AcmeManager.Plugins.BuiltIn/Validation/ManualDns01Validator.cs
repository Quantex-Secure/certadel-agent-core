using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Validation;

using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.BuiltIn.Validation;

public sealed record ManualDns01Options : PluginOptions
{
    /// <summary>How long to wait after logging the TXT record so the human can publish it.</summary>
    public TimeSpan PropagationDelay { get; init; } = TimeSpan.FromSeconds(60);
}

/// <summary>
/// DNS-01 validator that logs the TXT record the user must publish and waits
/// a configurable interval for propagation. Baseline option for any DNS
/// provider that doesn't have a dedicated plugin yet.
/// </summary>
public sealed class ManualDns01Validator(ILogger<ManualDns01Validator> logger) : IValidator
{
    public PluginMetadata Metadata { get; } = new(
        Id: "validation.dns-01.manual",
        Name: "DNS-01 (manual)",
        Description: "Logs the TXT record for an operator to publish manually, then waits.",
        Category: PluginCategory.Validation,
        Version: new Version(1, 0, 0));

    public ChallengeType ChallengeType => ChallengeType.Dns01;

    public async ValueTask PrepareAsync(ValidationContext ctx, CancellationToken ct)
    {
        var opts = (ManualDns01Options)ctx.Options;
        logger.LogWarning(
            "MANUAL DNS-01 — publish this TXT record now: name={Name} value={Value}. Waiting {Delay} for propagation.",
            ctx.Identifier, ctx.KeyAuthorization, opts.PropagationDelay);
        await Task.Delay(opts.PropagationDelay, ct);
    }

    public ValueTask CleanupAsync(ValidationContext ctx, CancellationToken ct)
    {
        logger.LogInformation(
            "Manual DNS-01 validation complete — you can now remove the TXT record at {Name}",
            ctx.Identifier);
        return ValueTask.CompletedTask;
    }
}