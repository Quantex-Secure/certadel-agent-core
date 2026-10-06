using AcmeManager.Plugins.Contracts.Installation;
using AcmeManager.Plugins.Iis;

namespace AcmeManager.Tests.Unit;

/// <summary>How the IIS installer decides where to look for the certificate it just bound.</summary>
public sealed class IisVerificationEndpointTests
{
    [Theory]
    [InlineData("*:443:shop.example.com", "127.0.0.1", 443)]
    [InlineData(":443:shop.example.com", "127.0.0.1", 443)]
    [InlineData("0.0.0.0:443:shop.example.com", "127.0.0.1", 443)]
    [InlineData("10.0.0.5:8443:shop.example.com", "10.0.0.5", 8443)]
    [InlineData("[::]:443:shop.example.com", "::1", 443)]
    [InlineData("[fe80::1]:443:shop.example.com", "fe80::1", 443)]
    [InlineData("[::1]:443:", "::1", 443)]
    [InlineData("garbage", "127.0.0.1", 443)]
    public void BindingAddress_ParsesIPv4_IPv6_AndWildcards(string bindingInfo, string host, int port)
    {
        Assert.Equal((host, port), IisInstaller.ParseBindingAddress(bindingInfo));
    }

    [Fact]
    public void DefaultEndpoints_UseTheBindingHostAsSni_AndTheCommonNameWhenHostless()
    {
        var targets = new List<BindingTarget>
        {
            new("Default Web Site", "*:443:shop.example.com", "shop.example.com"),
            new("Default Web Site", "*:443:", ""),
            new("Default Web Site", "*:443:shop.example.com", "shop.example.com"), // duplicate binding info
        };

        var endpoints = IisInstaller.DefaultEndpoints(targets, "cn.example.com");

        Assert.Equal(2, endpoints.Count);
        Assert.Contains(new VerifyEndpoint("127.0.0.1", 443, "shop.example.com"), endpoints);
        Assert.Contains(new VerifyEndpoint("127.0.0.1", 443, "cn.example.com"), endpoints);
    }
}