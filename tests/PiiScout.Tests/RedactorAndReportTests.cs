using System.Text.Json;
using PiiScout.Core;
using PiiScout.Core.Policy;
using PiiScout.Core.Reporting;
using PiiScout.Core.Scanning;

namespace PiiScout.Tests;

public class RedactorTests
{
    private readonly Redactor redactor = new();

    [Fact]
    public void MasksValuesAndKeepsTheRest()
    {
        var r = redactor.Redact("app.log", "login user=erika.muster84@gmx.de ip=93.184.216.34 order=88213\n");
        Assert.Equal("login user=e***@gmx.de ip=93.184.*.* order=88213\n", r.Text);
        Assert.Equal(2, r.Total);
    }

    [Fact]
    public void KeepsLineEndingsExactly()
    {
        var r = redactor.Redact("a.txt", "a erika@gmx.de\r\nb\r\n\r\nc jonas@web.de");
        Assert.Equal("a e***@gmx.de\r\nb\r\n\r\nc j***@web.de", r.Text);
    }

    [Fact]
    public void RedactedOutputScansClean()
    {
        foreach (var file in Directory.EnumerateFiles(T.SamplesDir, "*", SearchOption.AllDirectories))
        {
            var name = Path.GetRelativePath(T.SamplesDir, file);
            var redacted = redactor.Redact(name, File.ReadAllText(file)).Text;
            var rescan = new Scanner().ScanText(name, redacted, new ScanOptions { MinConfidence = Confidence.Low });
            Assert.True(!rescan.Active.Any(), $"{name} still contains: {string.Join(", ", rescan.Active.Select(m => m.DetectorId))}");
        }
    }

    [Fact]
    public void CsvStaysACsv()
    {
        var csv = File.ReadAllText(Path.Combine(T.SamplesDir, "crm-export.csv"));
        var redacted = redactor.Redact("crm-export.csv", csv).Text;
        var before = Scanner.SplitLines(csv).Select(l => FieldExtractor.SplitCsv(l, ';').Count);
        var after = Scanner.SplitLines(redacted).Select(l => FieldExtractor.SplitCsv(l, ';').Count);
        Assert.Equal(before, after);
        Assert.Contains("Rückruf erbeten", redacted); // free text without personal data stays
    }

    [Fact]
    public void JsonStaysValidJson()
    {
        var json = File.ReadAllText(Path.Combine(T.SamplesDir, "support-ticket.json"));
        var redacted = redactor.Redact("support-ticket.json", json).Text;
        using var doc = JsonDocument.Parse(redacted);
        Assert.Equal("SUP-2291", doc.RootElement.GetProperty("ticket").GetString());
        Assert.DoesNotContain("20692815242", redacted);
    }

    [Fact]
    public void Art9FieldValueIsReplacedInsideItsQuotes()
    {
        var r = redactor.Redact("x.json", "{\"religion\": \"evangelisch\"}");
        Assert.Equal("{\"religion\": \"[11 chars]\"}", r.Text);
    }

    [Fact]
    public void PseudonymsAreStableWithAKey()
    {
        var text = "from=erika@gmx.de\nto=erika@gmx.de\ncc=jonas@web.de\n";
        var a = redactor.Redact("m.log", text, RedactionMode.Pseudonymize, key: "secret").Text.Split('\n');
        var b = redactor.Redact("m.log", text, RedactionMode.Pseudonymize, key: "secret").Text.Split('\n');
        Assert.Equal(a, b);
        Assert.StartsWith("from=[EMAIL:", a[0]);
        Assert.Equal(a[0]["from=".Length..], a[1]["to=".Length..]);        // same person, same token
        Assert.NotEqual(a[0]["from=".Length..], a[2]["cc=".Length..]);
    }

    [Fact]
    public void TestDataIsKeptUnlessAsked()
    {
        const string text = "card=4111111111111111";
        Assert.Equal(text, redactor.Redact("t.txt", text).Text);
        Assert.Equal("card=Visa ****1111", redactor.Redact("t.txt", text, keepTestData: false).Text);
    }

    [Fact]
    public void LowConfidenceHitsAreRedactedByDefault()
    {
        // A scan hides "ref 86095742719" (no context), but redaction errs on the safe side
        Assert.Equal("ref *********19", redactor.Redact("t.txt", "ref 86095742719").Text);
    }
}

public class ReportTests
{
    private static ScanResult Samples() => new Scanner().Scan(T.SamplesDir, new ScanOptions
    {
        Ignore = IgnoreList.Parse(File.ReadAllText(Path.Combine(T.SamplesDir, ".piiscout-ignore"))),
        Exclude = ["README.md"],
        MinConfidence = Confidence.Low,
    });

    // Every raw value in the samples: none of them may appear in any report
    private static readonly string[] RawValues =
    [
        "erika.muster84@gmx.de", "DE83924884111604672105", "DE83 9248 8411 1604 6721 05", "4597 6020 4629 0718", "4597602046290718",
        "93.184.216.34", "16809624561", "77250771C010", "XT3H4M37P1", "20692815242", "F32.1", "0171 9876543", "14.03.1984",
        "Erika Muster", "Jonas Beispiel",
    ];

    [Theory]
    [InlineData("json")]
    [InlineData("markdown")]
    [InlineData("sarif")]
    public void ReportsNeverContainRawValues(string format)
    {
        var r = Samples();
        var text = format switch { "json" => ReportFormats.ToJson(r), "markdown" => ReportFormats.ToMarkdown(r), _ => ReportFormats.ToSarif(r) };
        foreach (var raw in RawValues)
            Assert.DoesNotContain(raw, text);
    }

    [Fact]
    public void SarifIsValidForCodeScanning()
    {
        using var doc = JsonDocument.Parse(ReportFormats.ToSarif(Samples()));
        var run = doc.RootElement.GetProperty("runs")[0];
        var rules = run.GetProperty("tool").GetProperty("driver").GetProperty("rules").EnumerateArray().ToList();
        var results = run.GetProperty("results").EnumerateArray().ToList();
        Assert.Equal("2.1.0", doc.RootElement.GetProperty("version").GetString());
        Assert.NotEmpty(results);
        foreach (var res in results)
        {
            var index = res.GetProperty("ruleIndex").GetInt32();
            Assert.Equal(rules[index].GetProperty("id").GetString(), res.GetProperty("ruleId").GetString());
            var uri = res.GetProperty("locations")[0].GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString()!;
            Assert.False(Path.IsPathRooted(uri));   // Code Scanning wants repository-relative paths
            Assert.DoesNotContain('\\', uri);
            Assert.Equal(16, res.GetProperty("partialFingerprints").GetProperty("piiValue/v1").GetString()!.Length);
        }
        Assert.All(rules, r => Assert.True(double.Parse(r.GetProperty("properties").GetProperty("security-severity").GetString()!, System.Globalization.CultureInfo.InvariantCulture) > 0));
        // Test data is left out, accepted findings are marked as suppressed
        Assert.DoesNotContain(results, r => r.GetProperty("locations")[0].GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString() == "fixtures/customers.json");
        Assert.Contains(results, r => r.TryGetProperty("suppressions", out _));
    }

    [Fact]
    public void MarkdownHasDataMapAndArt9Warning()
    {
        var md = ReportFormats.ToMarkdown(Samples());
        Assert.Contains("### Data map", md);
        Assert.Contains("| 🟣 Critical | `crm-export.csv` | `Konfession` | Special category field | 2 | 2 |", md);
        Assert.Contains("Art. 9 GDPR", md);
        Assert.Contains("Verzeichnis von Verarbeitungstätigkeiten", md);
        Assert.Contains("Accepted in `.piiscout-ignore`", md);
    }

    [Fact]
    public void CleanMarkdown()
    {
        var r = new Scanner().ScanText("x.txt", "nothing personal here");
        Assert.Contains("No personal data found", ReportFormats.ToMarkdown(r));
        Assert.Null(r.Worst);
    }

    [Fact]
    public void JsonHasMapAndFindings()
    {
        using var doc = JsonDocument.Parse(ReportFormats.ToJson(Samples()));
        Assert.Equal("critical", doc.RootElement.GetProperty("worst").GetString());
        Assert.True(doc.RootElement.GetProperty("dataMap").GetArrayLength() > 10);
        var first = doc.RootElement.GetProperty("findings")[0];
        Assert.True(first.TryGetProperty("masked", out _));
        Assert.False(first.TryGetProperty("value", out _));
    }
}
