namespace AcmeManager.Plugins.Linux;

/// <summary>Shared file-writing for the Linux installers.</summary>
internal static class LinuxInstall
{
    public static void WriteFileAtomic(string path, string content, bool ownerOnly) =>
        WriteFileAtomic(path, System.Text.Encoding.UTF8.GetBytes(content), ownerOnly);

    /// <summary>
    /// Writes <paramref name="content"/> to <paramref name="path"/> atomically
    /// (temp file + rename) so a service reading mid-write never sees a partial
    /// file. <paramref name="ownerOnly"/> chmods 0600 for key material (Unix only).
    /// </summary>
    public static void WriteFileAtomic(string path, byte[] content, bool ownerOnly) =>
        WriteFileAtomicKeepingPrevious(path, content, ownerOnly);

    public static Action WriteFileAtomicKeepingPrevious(string path, string content, bool ownerOnly) =>
        WriteFileAtomicKeepingPrevious(path, System.Text.Encoding.UTF8.GetBytes(content), ownerOnly);

    /// <summary>
    /// As <see cref="WriteFileAtomic(string, byte[], bool)"/>, but first snapshots
    /// the existing file so the write can be undone. Returns an action that
    /// restores the previous content (or removes the file if there was none) —
    /// what an installer hands the engine as its rollback.
    /// </summary>
    public static Action WriteFileAtomicKeepingPrevious(string path, byte[] content, bool ownerOnly)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        byte[]? previous = File.Exists(path) ? File.ReadAllBytes(path) : null;
        var previousMode = previous is not null && !OperatingSystem.IsWindows() ? File.GetUnixFileMode(path) : (UnixFileMode?)null;

        WriteReplacing(path, content, ownerOnly);

        return () =>
        {
            if (previous is null)
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
                return;
            }
            WriteReplacing(path, previous, ownerOnly);
            if (previousMode is { } mode && !OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, mode);
            }
        };
    }

    private static void WriteReplacing(string path, byte[] content, bool ownerOnly)
    {
        var temp = path + ".tmp";
        File.WriteAllBytes(temp, content);
        if (ownerOnly && !OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        File.Move(temp, path, overwrite: true);
    }
}