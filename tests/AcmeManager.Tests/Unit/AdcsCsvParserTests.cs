using AcmeManager.Service.Coverage;

namespace AcmeManager.Tests.Unit;

/// <summary>Parsing of certutil's CSV view of an AD CS database (the live call needs a CA).</summary>
public sealed class AdcsCsvParserTests
{
    private const string Sample =
        "\"Serial Number\",\"Certificate Hash\",\"Certificate Effective Date\",\"Certificate Expiration Date\",\"Issued Common Name\",\"Certificate Template\",\"Requester Name\"\n" +
        "\"1a00000002abcd\",\"aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd\",\"2026-01-15 10:00\",\"2027-01-15 10:00\",\"intranet.corp.local\",\"WebServer\",\"CORP\\svc-web\"\n" +
        "\"1a00000003ef01\",\"EMPTY\",\"2026-02-01 08:30\",\"2028-02-01 08:30\",\"Smith, John\",\"User\",\"CORP\\jsmith\"\n" +
        "\"\",\"\",\"\",\"\",\"\",\"\",\"\"\n" +
        "\"1a00000004\",\"00 11\",\"not a date\",\"2027-01-01\",\"broken.corp.local\",\"WebServer\",\"EMPTY\"\n";

    [Fact]
    public void Parse_ReadsRows_NormalisesThumbprints_AndSkipsUnusableOnes()
    {
        var certs = AdcsIssuedCertReader.ParseCsv(Sample);

        Assert.Equal(2, certs.Count);
        var web = certs[0];
        Assert.Equal("1a00000002abcd", web.SerialNumber);
        Assert.Equal("AABBCCDDEEFF00112233445566778899AABBCCDD", web.Thumbprint);
        Assert.Equal("intranet.corp.local", web.CommonName);
        Assert.Equal("WebServer", web.Template);
        Assert.Equal("CORP\\svc-web", web.Requester);
        Assert.Equal(2027, web.NotAfter.Year);

        var user = certs[1];
        Assert.Null(user.Thumbprint);           // EMPTY hash
        Assert.Equal("Smith, John", user.CommonName); // comma inside a quoted field
    }

    [Theory]
    [InlineData("1/15/2026 10:00 AM", "1/15/2027 10:00 AM")]   // en-US short date/time
    [InlineData("15.01.2026 10:00", "15.01.2027 10:00")]       // de-DE
    [InlineData("2026-01-15 10:00", "2027-01-15 10:00")]       // ISO-ish
    public void Parse_AcceptsTheDateShapesCertutilRenders(string from, string to)
    {
        var csv = "\"Serial Number\",\"Certificate Hash\",\"From\",\"To\",\"CN\"\n" +
                  $"\"01\",\"EMPTY\",\"{from}\",\"{to}\",\"x.corp\"\n";

        var (certs, skipped) = AdcsIssuedCertReader.ParseCsvWithDiagnostics(csv);

        Assert.Equal(0, skipped);
        var cert = Assert.Single(certs);
        Assert.Equal(15, cert.NotBefore.Day);
        Assert.Equal(2027, cert.NotAfter.Year);
    }

    [Fact]
    public void Parse_CountsRowsWhoseDatesItCannotRead()
    {
        var (certs, skipped) = AdcsIssuedCertReader.ParseCsvWithDiagnostics(
            "\"S\",\"H\",\"From\",\"To\",\"CN\"\n\"01\",\"EMPTY\",\"never\",\"ever\",\"x\"\n");
        Assert.Empty(certs);
        Assert.Equal(1, skipped);
    }

    [Fact]
    public void SplitCsvRow_HandlesQuotedCommasAndDoubledQuotes()
    {
        var fields = AdcsIssuedCertReader.SplitCsvRow("\"a,b\",\"say \"\"hi\"\"\",plain");
        Assert.Equal(["a,b", "say \"hi\"", "plain"], fields);
    }

    [Fact]
    public void Parse_EmptyOrHeaderOnly_IsEmpty()
    {
        Assert.Empty(AdcsIssuedCertReader.ParseCsv(""));
        Assert.Empty(AdcsIssuedCertReader.ParseCsv("\"Serial Number\",\"Certificate Hash\",\"a\",\"b\",\"c\"\n"));
    }
}