using System.Diagnostics;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Installation;
using AcmeManager.Plugins.Contracts.Storage;

using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.BuiltIn.Installation;

public sealed record ScriptInstallerOptions : PluginOptions
{
    /// <summary>
    /// Path to the script to execute. <c>.ps1</c> runs under PowerShell 7 (<c>pwsh</c>);
    /// <c>.sh</c> runs under <c>/bin/sh</c>. Other extensions run directly.
    /// </summary>
    public string ScriptPath { get; init; } = "";

    /// <summary>Verbatim arguments appended to the script invocation.</summary>
    public string Arguments { get; init; } = "";

    public string? WorkingDirectory { get; init; }

    public TimeSpan Timeout { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// What to check after the script runs, comma-separated: <c>host</c>,
    /// <c>host:port</c>, or <c>name@host:port</c> (name = SNI). A script's effect is
    /// opaque to the agent, so nothing is verified unless you name the endpoints.
    /// </summary>
    public string VerifyEndpoints { get; init; } = "";
}

/// <summary>
/// Installer plugin that runs a user-supplied script after issuance. Context
/// is exposed via environment variables so scripts can be written without
/// fragile string templating:
/// <list type="bullet">
///   <item><c>ACME_COMMON_NAME</c>, <c>ACME_NOT_BEFORE</c>, <c>ACME_NOT_AFTER</c>,
///         <c>ACME_THUMBPRINT</c></item>
///   <item><c>ACME_SAN_COUNT</c>, <c>ACME_SAN_0</c>, <c>ACME_SAN_1</c>, ...</item>
///   <item><c>ACME_STORE_&lt;PLUGIN_ID_UPPER_UNDERSCORED&gt;</c> for each
///         store that ran — e.g. <c>ACME_STORE_STORE_PFX</c> = path to the .pfx.</item>
/// </list>
/// </summary>
public sealed class ScriptInstaller(ILogger<ScriptInstaller> logger) : IInstaller
{
    public PluginMetadata Metadata { get; } = new(
        Id: "installer.script",
        Name: "Script",
        Description: "Runs a user-supplied PowerShell / shell / executable after issuance.",
        Category: PluginCategory.Installation,
        Version: new Version(1, 0, 0));

    public async ValueTask<InstallResult> InstallAsync(CertificateBundle bundle, InstallContext ctx, CancellationToken ct)
    {
        var opts = (ScriptInstallerOptions)ctx.Options;
        // Validate the operator's endpoint list before the script has any effect.
        var verifyEndpoints = VerificationOptions.Parse(opts.VerifyEndpoints, 443, bundle.CommonName);
        if (string.IsNullOrWhiteSpace(opts.ScriptPath))
        {
            throw new InvalidOperationException("ScriptInstaller: ScriptPath is required");
        }
        if (!File.Exists(opts.ScriptPath))
        {
            throw new FileNotFoundException($"ScriptInstaller: script not found at '{opts.ScriptPath}'");
        }

        var (exe, leadingArgs) = ResolveInterpreter(opts.ScriptPath);
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = string.IsNullOrEmpty(opts.Arguments)
                ? leadingArgs
                : $"{leadingArgs} {opts.Arguments}".Trim(),
            WorkingDirectory = opts.WorkingDirectory ?? Path.GetDirectoryName(opts.ScriptPath) ?? "",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        PopulateEnvironment(psi, bundle, ctx.StoreReferences);

        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start '{exe}'");

        var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = proc.StandardError.ReadToEndAsync(ct);

        using var timeoutCts = new CancellationTokenSource(opts.Timeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        try
        {
            await proc.WaitForExitAsync(linked.Token);
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"Script '{opts.ScriptPath}' exceeded timeout {opts.Timeout}");
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        if (proc.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"Script '{opts.ScriptPath}' exited {proc.ExitCode}. stderr: {stderr.Trim()}");
        }

        logger.LogInformation(
            "Installer script completed (exit 0, {OutLen}B stdout)", stdout.Length);
        // A script's effect is opaque; the operator can name what to check.
        return InstallResult.Ok($"'{opts.ScriptPath}' exited 0") with
        {
            Endpoints = verifyEndpoints,
        };
    }

    private static (string Exe, string LeadingArgs) ResolveInterpreter(string scriptPath)
    {
        var ext = Path.GetExtension(scriptPath).ToLowerInvariant();
        return ext switch
        {
            ".ps1" => (OperatingSystem.IsWindows() ? "pwsh.exe" : "pwsh",
                       $"-NoProfile -ExecutionPolicy Bypass -File \"{scriptPath}\""),
            ".sh" => ("/bin/sh", $"\"{scriptPath}\""),
            _ => (scriptPath, string.Empty),
        };
    }

    private static void PopulateEnvironment(
        ProcessStartInfo psi,
        CertificateBundle bundle,
        IReadOnlyDictionary<string, string> storeRefs)
    {
        psi.Environment["ACME_COMMON_NAME"] = bundle.CommonName;
        psi.Environment["ACME_THUMBPRINT"] = bundle.Thumbprint;
        psi.Environment["ACME_NOT_BEFORE"] = bundle.NotBefore.ToString("O");
        psi.Environment["ACME_NOT_AFTER"] = bundle.NotAfter.ToString("O");
        psi.Environment["ACME_SAN_COUNT"] = bundle.SubjectAlternativeNames.Count.ToString();
        for (var i = 0; i < bundle.SubjectAlternativeNames.Count; i++)
        {
            psi.Environment[$"ACME_SAN_{i}"] = bundle.SubjectAlternativeNames[i];
        }
        foreach (var kv in storeRefs)
        {
            var key = "ACME_STORE_" + kv.Key.ToUpperInvariant().Replace('.', '_').Replace('-', '_');
            psi.Environment[key] = kv.Value;
        }
    }
}