using System.Runtime.CompilerServices;

using AcmeManager.Core.Storage;

namespace AcmeManager.Tests;

/// <summary>
/// Points the agent's data directory at a per-run temp folder before any test
/// runs. The integration tests boot the real host, which otherwise creates (and
/// ACL-hardens) the production data directory under ProgramData — which fails
/// outright once a real agent is installed on the machine, and must never touch
/// a live installation's database, secrets key, or endpoint certificate anyway.
/// </summary>
internal static class TestDataRoot
{
    public static string Path { get; } =
        System.IO.Path.Combine(System.IO.Path.GetTempPath(), "acme-manager-tests", Guid.NewGuid().ToString("N"));

    [ModuleInitializer]
    internal static void Initialize()
    {
        Directory.CreateDirectory(Path);
        Environment.SetEnvironmentVariable(DataPaths.RootOverrideVariable, Path);
    }
}