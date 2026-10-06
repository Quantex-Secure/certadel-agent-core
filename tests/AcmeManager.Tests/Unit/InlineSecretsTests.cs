using System.Text.Json.Nodes;

using AcmeManager.Core.Engine;
using AcmeManager.Core.Plugins;
using AcmeManager.Plugins.Linux.Synology;

using Microsoft.Extensions.DependencyInjection;

namespace AcmeManager.Tests.Unit;

public sealed class InlineSecretsTests
{
    private const string Renewal = "NAS cert";
    private const string AdminSecret = @"Synology DSM: EXAMPLE\admin (NAS cert)";

    private static PluginCatalog Catalog()
    {
        var services = new ServiceCollection();
        services.AddPluginCatalog(b => b.AddInstaller<DsmInstaller, DsmInstallerOptions>("installer.synology-dsm"));
        return services.BuildServiceProvider().GetRequiredService<PluginCatalog>();
    }

    private static JsonObject Options(string json) =>
        JsonNode.Parse(json)!.AsArray()[0]!["options"]!.AsObject();

    private static string Step(string options) =>
        $$"""[{"pluginId":"installer.synology-dsm","options":{{options}}}]""";

    [Fact]
    public async Task Password_BecomesAPerRenewalSecret_AndLeavesTheStep()
    {
        var json = Step("""{"account":"EXAMPLE\\admin","password":"hunter2","services":"*"}""");

        var extracted = InlineSecrets.Extract(Catalog(), json, Renewal);

        Assert.Equal([new PendingSecret(AdminSecret, "hunter2")], extracted.Secrets);
        var options = Options(extracted.Json);
        Assert.False(options.ContainsKey("password"));
        Assert.Equal(AdminSecret, (string)options["passwordSecretName"]!);
        Assert.Equal("*", (string)options["services"]!);
        Assert.DoesNotContain("hunter2", extracted.Json);

        var stored = new Dictionary<string, string>();
        await extracted.CommitAsync((n, v, _) => { stored[n] = v; return Task.CompletedTask; }, CancellationToken.None);
        Assert.Equal("hunter2", stored[AdminSecret]);
    }

    [Fact]
    public void Extract_IsPure_NothingIsWrittenUntilCommit()
    {
        var extracted = InlineSecrets.Extract(Catalog(), Step("""{"account":"a","password":"x"}"""), Renewal);

        Assert.Single(extracted.Secrets); // pending only — the caller commits after validating
    }

    [Fact]
    public void SameAccount_InDifferentRenewals_GetsDifferentSecrets()
    {
        var json = Step("""{"account":"EXAMPLE\\admin","password":"x"}""");

        var a = InlineSecrets.Extract(Catalog(), json, "NAS cert").Secrets.Single().Name;
        var b = InlineSecrets.Extract(Catalog(), json, "Photos cert").Secrets.Single().Name;

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void BlankPassword_KeepsTheReferenceTheClientSent()
    {
        var extracted = InlineSecrets.Extract(Catalog(),
            Step("""{"account":"a","password":"","passwordSecretName":"Synology DSM: a (NAS cert)"}"""), Renewal);

        Assert.Empty(extracted.Secrets);
        Assert.Equal("Synology DSM: a (NAS cert)", (string)Options(extracted.Json)["passwordSecretName"]!);
        Assert.False(Options(extracted.Json).ContainsKey("password"));
    }

    [Fact]
    public void BlankPassword_WithoutReference_RestoresTheStoredReference()
    {
        var stored = Step("""{"account":"a","passwordSecretName":"Synology DSM: a (NAS cert)"}""");

        var extracted = InlineSecrets.Extract(Catalog(), Step("""{"account":"a","password":""}"""), Renewal, stored);

        Assert.Equal("Synology DSM: a (NAS cert)", (string)Options(extracted.Json)["passwordSecretName"]!);
    }

    [Fact]
    public void CaseVariantDuplicateKeys_AreAllRemoved()
    {
        var extracted = InlineSecrets.Extract(Catalog(),
            Step("""{"account":"a","password":"one","Password":"two","PASSWORD":"three"}"""), Renewal);

        Assert.Equal("one", extracted.Secrets.Single().Value); // camelCase key wins
        Assert.DoesNotContain("two", extracted.Json);
        Assert.DoesNotContain("three", extracted.Json);
        Assert.DoesNotContain("\"one\"", extracted.Json);
    }

    [Theory]
    [InlineData("""{"password":"x"}""")]                          // no account
    [InlineData("""{"account":"  ","password":"x"}""")]           // blank account
    [InlineData("""{"account":"a\u0007b","password":"x"}""")]     // control character
    public void UnsafeOrMissingAccount_IsRefused(string options)
    {
        Assert.Throws<InlineSecretException>(() => InlineSecrets.Extract(Catalog(), Step(options), Renewal));
    }

    [Fact]
    public void OverlongAccount_IsRefused()
    {
        var account = new string('a', 101);

        Assert.Throws<InlineSecretException>(() =>
            InlineSecrets.Extract(Catalog(), Step($$"""{"account":"{{account}}","password":"x"}"""), Renewal));
    }

    [Fact]
    public void MissingRenewalName_IsRefused()
    {
        Assert.Throws<InlineSecretException>(() =>
            InlineSecrets.Extract(Catalog(), Step("""{"account":"a","password":"x"}"""), " "));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("""[{"pluginId":"installer.unknown","options":{"password":"x"}}]""")]
    [InlineData("""[{"pluginId":"installer.synology-dsm","options":{"account":"a"}}]""")]
    public void UnrelatedInput_PassesThroughUntouched(string json)
    {
        var extracted = InlineSecrets.Extract(Catalog(), json, Renewal);

        Assert.Equal(json, extracted.Json);
        Assert.Empty(extracted.Secrets);
    }

    [Fact]
    public void SecretNameSibling_IsReportedAsManaged()
    {
        var props = typeof(DsmInstallerOptions).GetProperties().ToDictionary(p => p.Name);

        Assert.True(InlineSecrets.IsManagedSecretName(props[nameof(DsmInstallerOptions.PasswordSecretName)]));
        Assert.False(InlineSecrets.IsManagedSecretName(props[nameof(DsmInstallerOptions.Account)]));
    }
}
