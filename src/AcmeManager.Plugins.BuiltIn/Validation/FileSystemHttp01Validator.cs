using System.Text.RegularExpressions;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Validation;

using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.BuiltIn.Validation;

public sealed record FileSystemHttp01Options : PluginOptions
{
    /// <summary>
    /// Absolute path to the web root the existing HTTP server already serves
    /// — e.g. <c>C:\inetpub\wwwroot</c> or <c>/var/www/html</c>. The validator
    /// drops the challenge file at <c>&lt;webroot&gt;/.well-known/acme-challenge/&lt;token&gt;</c>.
    /// </summary>
    public string WebrootPath { get; init; } = "";
}

/// <summary>
/// HTTP-01 validator for hosts that already have a web server bound to port 80
/// (IIS, nginx, Apache). Writes the challenge token into the web root so the
/// existing server serves it. Cleans up after validation.
///
/// The token comes from the ACME server and is used as a file name, so it is
/// validated against the RFC 8555 token alphabet and the resulting path is
/// confined to the challenge directory: a hostile or compromised CA must not be
/// able to turn a challenge into an arbitrary file write as the service account.
/// </summary>
public sealed partial class FileSystemHttp01Validator(ILogger<FileSystemHttp01Validator> logger) : IValidator
{
    public PluginMetadata Metadata { get; } = new(
        Id: "validation.http-01.filesystem",
        Name: "HTTP-01 (file system)",
        Description: "Drops the challenge token into a web root that an existing HTTP server serves.",
        Category: PluginCategory.Validation,
        Version: new Version(1, 0, 0));

    public ChallengeType ChallengeType => ChallengeType.Http01;

    public ValueTask PrepareAsync(ValidationContext ctx, CancellationToken ct)
    {
        var opts = (FileSystemHttp01Options)ctx.Options;
        if (string.IsNullOrWhiteSpace(opts.WebrootPath))
        {
            throw new InvalidOperationException("FileSystemHttp01: WebrootPath is required");
        }

        var file = ChallengeFilePath(opts.WebrootPath, ctx.Token);
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, ctx.KeyAuthorization);

        logger.LogInformation(
            "Published HTTP-01 challenge for {Identifier} at {File}",
            ctx.Identifier, file);

        return ValueTask.CompletedTask;
    }

    public ValueTask CleanupAsync(ValidationContext ctx, CancellationToken ct)
    {
        var opts = (FileSystemHttp01Options)ctx.Options;
        string file;
        try
        {
            file = ChallengeFilePath(opts.WebrootPath, ctx.Token);
        }
        catch (InvalidOperationException ex)
        {
            // Never written (Prepare refused it), so nothing to remove.
            logger.LogWarning(ex, "Skipping cleanup of an invalid challenge token");
            return ValueTask.CompletedTask;
        }

        try
        {
            if (File.Exists(file)) File.Delete(file);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to clean up challenge file {File}", file);
        }
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// The absolute path of the challenge file for <paramref name="token"/> under
    /// <paramref name="webroot"/>. Throws if the token is not a plain base64url
    /// token or the resolved path would escape the challenge directory.
    /// </summary>
    internal static string ChallengeFilePath(string webroot, string token)
    {
        if (!IsValidToken(token))
        {
            throw new InvalidOperationException(
                "FileSystemHttp01: the ACME server sent a challenge token that is not a plain base64url token; refusing to use it as a file name.");
        }

        var dir = Path.GetFullPath(Path.Combine(webroot, ".well-known", "acme-challenge"));
        var file = Path.GetFullPath(Path.Combine(dir, token));
        var dirWithSeparator = dir.EndsWith(Path.DirectorySeparatorChar) ? dir : dir + Path.DirectorySeparatorChar;
        if (!file.StartsWith(dirWithSeparator, StringComparison.Ordinal)
            || !string.Equals(Path.GetFileName(file), token, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "FileSystemHttp01: the challenge file path resolved outside the challenge directory; refusing.");
        }
        return file;
    }

    private static readonly HashSet<string> WindowsReservedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    /// <summary>
    /// RFC 8555 §8.3: tokens are base64url without padding, at least 128 bits of
    /// entropy. Windows device names (<c>NUL</c>, <c>COM1</c>, …) fit the alphabet
    /// but would resolve to a device rather than a file, so they are refused too.
    /// </summary>
    internal static bool IsValidToken(string? token) =>
        !string.IsNullOrEmpty(token)
        && token.Length <= 256
        && TokenPattern().IsMatch(token)
        && !WindowsReservedNames.Contains(token);

    [GeneratedRegex("^[A-Za-z0-9_-]+$")]
    private static partial Regex TokenPattern();
}