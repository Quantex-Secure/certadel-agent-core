using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Sources;
using AcmeManager.Plugins.Contracts.Storage;
using AcmeManager.Plugins.Contracts.Validation;

namespace AcmeManager.Tests.Stubs;

/// <summary>
/// HTTP-01 validator that does nothing — the stub CA auto-validates challenges,
/// so no challenge actually needs publishing. Lets a renewal run end-to-end
/// without a real DNS/HTTP challenge or a propagation delay.
/// </summary>
public sealed record NoOpValidatorOptions : PluginOptions;

public sealed class NoOpHttp01Validator : IValidator
{
    public const string PluginId = "validation.test.noop";

    public PluginMetadata Metadata { get; } = new(
        Id: PluginId,
        Name: "No-op (test)",
        Description: "Does nothing; paired with the stub CA that auto-validates challenges.",
        Category: PluginCategory.Validation,
        Version: new Version(1, 0, 0));

    public ChallengeType ChallengeType => ChallengeType.Http01;

    public ValueTask PrepareAsync(ValidationContext ctx, CancellationToken ct) => ValueTask.CompletedTask;

    public ValueTask CleanupAsync(ValidationContext ctx, CancellationToken ct) => ValueTask.CompletedTask;
}

/// <summary>Store options carrying the message the throwing store will raise.</summary>
public sealed record ThrowingStoreOptions : PluginOptions
{
    public string FailureMessage { get; init; } = "Simulated store failure";
}

/// <summary>Store plugin whose <see cref="StoreAsync"/> always throws — drives the engine's failure path.</summary>
public sealed class ThrowingStore : IStore
{
    public const string PluginId = "store.test.throwing";

    public PluginMetadata Metadata { get; } = new(
        Id: PluginId,
        Name: "Throwing store (test)",
        Description: "Always throws on store to exercise the engine's failure handling.",
        Category: PluginCategory.Store,
        Version: new Version(1, 0, 0));

    public ValueTask<StoreResult> StoreAsync(CertificateBundle bundle, StoreContext ctx, CancellationToken ct)
    {
        var opts = (ThrowingStoreOptions)ctx.Options;
        throw new InvalidOperationException(opts.FailureMessage);
    }

    public ValueTask<CertificateBundle?> RetrieveAsync(string identifier, StoreContext ctx, CancellationToken ct) =>
        ValueTask.FromResult<CertificateBundle?>(null);

    public ValueTask DeleteAsync(string identifier, StoreContext ctx, CancellationToken ct) => ValueTask.CompletedTask;
}

/// <summary>
/// Source that blocks inside <see cref="ResolveAsync"/> until released, so a test
/// can hold one renewal run open and prove a second concurrent run is rejected by
/// the single-flight guard. Falls back to the configured identifiers once released.
/// </summary>
public sealed record GatedSourceOptions : PluginOptions
{
    public IReadOnlyList<string> Identifiers { get; init; } = [];
}

public sealed class GatedSource : ISource
{
    public const string PluginId = "source.test.gated";

    private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Completes once a run has entered <see cref="ResolveAsync"/>.</summary>
    public Task Entered => _entered.Task;

    /// <summary>Lets the blocked <see cref="ResolveAsync"/> proceed.</summary>
    public void Release() => _release.TrySetResult();

    public PluginMetadata Metadata { get; } = new(
        Id: PluginId,
        Name: "Gated source (test)",
        Description: "Blocks until released; used to hold a renewal run open for single-flight tests.",
        Category: PluginCategory.Source,
        Version: new Version(1, 0, 0));

    public async ValueTask<SourceResult> ResolveAsync(SourceContext ctx, CancellationToken ct)
    {
        var opts = (GatedSourceOptions)ctx.Options;
        _entered.TrySetResult();
        await _release.Task.WaitAsync(ct);
        return new SourceResult(opts.Identifiers, opts.Identifiers.Count > 0 ? opts.Identifiers[0] : null);
    }
}

/// <summary>Satisfies <c>PfxFileStore</c>'s <see cref="ISecretResolver"/> dependency; never used since tests use literal paths.</summary>
public sealed class ThrowingSecretResolver : ISecretResolver
{
    public Task<string> ResolveAsync(string name, CancellationToken ct) =>
        throw new KeyNotFoundException(name);
}
