using AcmeManager.Plugins.BuiltIn.Sources;
using AcmeManager.Plugins.Contracts.Sources;

namespace AcmeManager.Tests.Unit;

public sealed class ManualSourceTests
{
    [Fact]
    public async Task Resolve_ReturnsConfiguredIdentifiers()
    {
        var source = new ManualSource();
        var opts = new ManualSourceOptions
        {
            Identifiers = ["example.com", "www.example.com"],
        };

        var result = await source.ResolveAsync(new SourceContext(opts), default);

        Assert.Equal(["example.com", "www.example.com"], result.Identifiers);
        Assert.Equal("example.com", result.CommonName);
    }

    [Fact]
    public async Task Resolve_UsesConfiguredCommonName_WhenProvided()
    {
        var source = new ManualSource();
        var opts = new ManualSourceOptions
        {
            Identifiers = ["a.com", "b.com"],
            CommonName = "b.com",
        };

        var result = await source.ResolveAsync(new SourceContext(opts), default);

        Assert.Equal("b.com", result.CommonName);
    }

    [Fact]
    public async Task Resolve_Throws_OnEmptyIdentifiers()
    {
        var source = new ManualSource();
        var opts = new ManualSourceOptions { Identifiers = [] };

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await source.ResolveAsync(new SourceContext(opts), default));
    }
}