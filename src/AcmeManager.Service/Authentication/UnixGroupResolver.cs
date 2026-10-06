using System.Diagnostics;
using System.Text.RegularExpressions;

namespace AcmeManager.Service.Authentication;

/// <summary>
/// Resolves the Unix groups a user belongs to, so the <c>Auth:AllowedGroup</c>
/// decision can be made for PAM-authenticated users exactly as it is for Windows.
/// </summary>
public interface IUnixGroupResolver
{
    /// <summary>
    /// Group names for <paramref name="username"/> (primary + supplementary, as
    /// NSS resolves them — local files, SSSD, LDAP, …). Throws if membership can't
    /// be determined; callers must treat that as "not authorized".
    /// </summary>
    Task<IReadOnlyList<string>> ResolveAsync(string username, CancellationToken ct);
}

/// <summary>
/// Default resolver: runs <c>id -Gn &lt;user&gt;</c>. Using the coreutils binary
/// (rather than P/Invoking <c>getgrouplist</c>/<c>getgrgid</c>) sidesteps the
/// glibc-vs-musl struct-layout differences and follows whatever NSS sources the
/// host is configured with. The username is passed as a discrete argument (no
/// shell), and only names that are valid POSIX account names are accepted.
/// </summary>
public sealed partial class IdCommandGroupResolver : IUnixGroupResolver
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    public async Task<IReadOnlyList<string>> ResolveAsync(string username, CancellationToken ct)
    {
        if (!IsValidAccountName(username))
        {
            throw new ArgumentException($"'{username}' is not a valid account name.", nameof(username));
        }

        var psi = new ProcessStartInfo
        {
            FileName = "id",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("-Gn");
        psi.ArgumentList.Add(username);

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start 'id'.");

        var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = process.StandardError.ReadToEndAsync(ct);

        using var timeoutCts = new CancellationTokenSource(Timeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
        try
        {
            await process.WaitForExitAsync(linked.Token);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // Already exited.
            }
            throw;
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"'id -Gn {username}' exited {process.ExitCode}: {stderr.Trim()}");
        }
        return ParseIdOutput(stdout);
    }

    /// <summary>Splits <c>id -Gn</c> output ("root sudo docker\n") into distinct names.</summary>
    internal static IReadOnlyList<string> ParseIdOutput(string output) =>
        output
            .Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)
            .ToList();

    /// <summary>
    /// POSIX portable account names plus the characters real directories use
    /// (<c>.</c>, <c>@</c> for UPN-style SSSD users, <c>\</c> for DOMAIN\user, <c>$</c>
    /// for machine accounts). Must not start with <c>-</c> so it can never read as an option.
    /// </summary>
    internal static bool IsValidAccountName(string username) =>
        !string.IsNullOrEmpty(username) && username.Length <= 256 && AccountName().IsMatch(username);

    [GeneratedRegex(@"^[A-Za-z0-9_][A-Za-z0-9_.@\\$-]*$")]
    private static partial Regex AccountName();
}