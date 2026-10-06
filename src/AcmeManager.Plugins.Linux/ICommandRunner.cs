using System.Diagnostics;

namespace AcmeManager.Plugins.Linux;

/// <summary>Runs a shell reload/restart command. A seam so installers are testable
/// without actually invoking systemctl.</summary>
public interface ICommandRunner
{
    /// <summary>Runs the command; throws on non-zero exit (with stderr) or timeout.</summary>
    Task RunAsync(string command, TimeSpan timeout, CancellationToken ct);

    /// <summary>
    /// Runs an executable with discrete arguments — no shell, so no argument can
    /// ever be interpreted as a command. Use this for anything built from
    /// configuration values; reserve the shell form for operator-authored
    /// reload commands.
    /// </summary>
    Task RunAsync(string file, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct);
}

/// <summary>Runs a command via <c>/bin/sh -c</c> (Linux). Captures stderr and
/// enforces a timeout. Only invoked on Linux at runtime; the installers gate on
/// <see cref="OperatingSystem.IsLinux"/> via their capability check.</summary>
public sealed class ShellCommandRunner : ICommandRunner
{
    public Task RunAsync(string command, TimeSpan timeout, CancellationToken ct) =>
        RunProcessAsync("/bin/sh", ["-c", command], $"/bin/sh -c {command}", timeout, ct);

    public Task RunAsync(string file, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct) =>
        RunProcessAsync(file, arguments, $"{file} {string.Join(' ', arguments)}", timeout, ct);

    private static async Task RunProcessAsync(
        string file, IReadOnlyList<string> arguments, string command, TimeSpan timeout, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(file)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
        {
            psi.ArgumentList.Add(argument);
        }

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start '{command}'.");

        // Read both streams concurrently to avoid a full-pipe deadlock.
        var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = process.StandardError.ReadToEndAsync(ct);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
            throw new TimeoutException($"Command '{command}' did not finish within {timeout}.");
        }

        if (process.ExitCode != 0)
        {
            var stderr = (await stderrTask).Trim();
            throw new InvalidOperationException(
                $"Command '{command}' failed (exit {process.ExitCode}){(stderr.Length > 0 ? $": {stderr}" : ".")}");
        }
    }
}