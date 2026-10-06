using System.Collections.Concurrent;
using System.Diagnostics;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Validation;

using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.BuiltIn.Validation;

public sealed record ScriptDns01Options : PluginOptions
{
    /// <summary>Command run to PUBLISH the TXT record. Receives the challenge details
    /// as environment variables (see the validator summary). Required.</summary>
    public string AddCommand { get; init; } = "";

    /// <summary>Command run to REMOVE the TXT record on cleanup. Optional.</summary>
    public string RemoveCommand { get; init; } = "";

    /// <summary>Wait this long after the add command before letting the CA validate.</summary>
    public TimeSpan PropagationDelay { get; init; } = TimeSpan.FromSeconds(60);

    public TimeSpan Timeout { get; init; } = TimeSpan.FromMinutes(2);
}

/// <summary>
/// DNS-01 validator that shells out to a user-supplied command to publish/remove the
/// <c>_acme-challenge</c> TXT — the escape hatch for any DNS provider without a native
/// plugin (and a way to reuse existing hook scripts). The command is run via the OS
/// shell with these environment variables:
/// <list type="bullet">
/// <item><c>ACME_DNS_FQDN</c> — the record name, e.g. <c>_acme-challenge.example.com</c></item>
/// <item><c>ACME_DNS_VALUE</c> — the TXT value to set</item>
/// <item><c>ACME_DNS_DOMAIN</c> — the identifier being validated</item>
/// <item><c>ACME_DNS_TOKEN</c> — the raw ACME token</item>
/// </list>
/// </summary>
public sealed class ScriptDns01Validator(ILogger<ScriptDns01Validator> logger) : IValidator
{
    private readonly ConcurrentDictionary<string, ValidationContext> _active = new();

    public PluginMetadata Metadata { get; } = new(
        Id: "validation.dns-01.script",
        Name: "DNS-01 (custom script)",
        Description: "Runs your add/remove command to publish the TXT — for any DNS provider without a native plugin.",
        Category: PluginCategory.Validation,
        Version: new Version(1, 0, 0));

    public ChallengeType ChallengeType => ChallengeType.Dns01;

    public async ValueTask PrepareAsync(ValidationContext ctx, CancellationToken ct)
    {
        var opts = (ScriptDns01Options)ctx.Options;
        if (string.IsNullOrWhiteSpace(opts.AddCommand))
        {
            throw new InvalidOperationException("ScriptDns01: AddCommand is required.");
        }

        await RunAsync(opts.AddCommand, ctx, opts.Timeout, ct);
        _active[ctx.Token] = ctx;
        logger.LogInformation("Script DNS-01: published {Fqdn} via add command; waiting {Delay}s",
            RecordFqdn(ctx.Identifier), opts.PropagationDelay.TotalSeconds);

        if (opts.PropagationDelay > TimeSpan.Zero)
        {
            await Task.Delay(opts.PropagationDelay, ct);
        }
    }

    public async ValueTask CleanupAsync(ValidationContext ctx, CancellationToken ct)
    {
        if (!_active.TryRemove(ctx.Token, out _))
        {
            return;
        }
        var opts = (ScriptDns01Options)ctx.Options;
        if (string.IsNullOrWhiteSpace(opts.RemoveCommand))
        {
            return;
        }
        try
        {
            await RunAsync(opts.RemoveCommand, ctx, opts.Timeout, ct);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Script DNS-01: remove command failed for {Fqdn}", RecordFqdn(ctx.Identifier));
        }
    }

    private static string RecordFqdn(string identifier) => identifier.TrimEnd('.');

    private async Task RunAsync(string command, ValidationContext ctx, TimeSpan timeout, CancellationToken ct)
    {
        var psi = OperatingSystem.IsWindows()
            ? new ProcessStartInfo("cmd.exe")
            : new ProcessStartInfo("/bin/sh");
        if (OperatingSystem.IsWindows())
        {
            psi.ArgumentList.Add("/c");
        }
        else
        {
            psi.ArgumentList.Add("-c");
        }
        psi.ArgumentList.Add(command);
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        psi.Environment["ACME_DNS_FQDN"] = RecordFqdn(ctx.Identifier);
        psi.Environment["ACME_DNS_VALUE"] = ctx.KeyAuthorization;
        psi.Environment["ACME_DNS_DOMAIN"] = ctx.Identifier.TrimEnd('.');
        psi.Environment["ACME_DNS_TOKEN"] = ctx.Token;

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Script DNS-01: failed to start '{command}'.");

        var stderr = process.StandardError.ReadToEndAsync(ct);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
            throw new TimeoutException($"Script DNS-01: '{command}' exceeded {timeout}.");
        }

        if (process.ExitCode != 0)
        {
            var err = (await stderr).Trim();
            throw new InvalidOperationException(
                $"Script DNS-01: command failed (exit {process.ExitCode}){(err.Length > 0 ? $": {err}" : ".")}");
        }
    }
}