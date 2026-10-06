using AcmeManager.Core.Plugins;
using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Sources;

namespace AcmeManager.Tests.Unit;

public sealed class PluginCatalogTests
{
    public sealed record FakeOptions : PluginOptions
    {
        public string Value { get; init; } = "default";
        public int Number { get; init; }
    }

    public sealed class FakeSourcePlugin : ISource
    {
        public PluginMetadata Metadata { get; } = new(
            "test.fake.source", "Fake", "", PluginCategory.Source, new Version(1, 0));

        public ValueTask<SourceResult> ResolveAsync(SourceContext ctx, CancellationToken ct) =>
            throw new NotSupportedException();
    }

    private static PluginCatalog BuildCatalog() => new(
    [
        new PluginRegistration(
            Id: "test.fake.source",
            Category: PluginCategory.Source,
            ImplementationType: typeof(FakeSourcePlugin),
            OptionsType: typeof(FakeOptions),
            DefaultOptionsFactory: () => new FakeOptions()),
    ]);

    [Fact]
    public void Get_ReturnsRegistration_ForKnownId()
    {
        var catalog = BuildCatalog();
        var reg = catalog.Get("test.fake.source");
        Assert.Equal(PluginCategory.Source, reg.Category);
        Assert.Equal(typeof(FakeOptions), reg.OptionsType);
    }

    [Fact]
    public void Get_Throws_ForUnknownId()
    {
        var catalog = BuildCatalog();
        Assert.Throws<KeyNotFoundException>(() => catalog.Get("nope"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("{}")]
    [InlineData("null")]
    public void DeserializeOptions_ReturnsDefault_ForEmptyOrTrivialJson(string? json)
    {
        var catalog = BuildCatalog();
        var opts = (FakeOptions)catalog.DeserializeOptions("test.fake.source", json);
        Assert.Equal("default", opts.Value);
        Assert.Equal(0, opts.Number);
    }

    [Fact]
    public void DeserializeOptions_ReadsCamelCaseJson()
    {
        var catalog = BuildCatalog();
        var json = """{"value":"custom","number":42}""";
        var opts = (FakeOptions)catalog.DeserializeOptions("test.fake.source", json);
        Assert.Equal("custom", opts.Value);
        Assert.Equal(42, opts.Number);
    }

    [Fact]
    public void SerializeOptions_RoundTrips()
    {
        var catalog = BuildCatalog();
        var original = new FakeOptions { Value = "x", Number = 7 };
        var json = catalog.SerializeOptions(original);
        var loaded = (FakeOptions)catalog.DeserializeOptions("test.fake.source", json);
        Assert.Equal(original, loaded);
    }

    [Fact]
    public void Builder_RejectsDuplicateId()
    {
        var builder = new PluginCatalogBuilder();
        builder.AddSource<FakeSourcePlugin, FakeOptions>("dup");
        Assert.Throws<InvalidOperationException>(
            () => builder.AddSource<FakeSourcePlugin, FakeOptions>("dup"));
    }
}