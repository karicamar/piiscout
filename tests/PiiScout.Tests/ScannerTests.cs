using System.Text;
using PiiScout.Core;
using PiiScout.Core.Policy;
using PiiScout.Core.Scanning;

namespace PiiScout.Tests;

public class FieldExtractorTests
{
    [Fact]
    public void CsvHeaderNamesBecomeFields()
    {
        var x = FieldExtractor.For("customers.csv", "id;Name;IBAN");
        Assert.True(x.IsTabular);
        x.Context("id;Name;IBAN");
        var line = x.Context("1;\"Demir; Leyla\";DE34874175220147165935");
        Assert.True(line.Tabular);
        Assert.Equal(["id", "Name", "IBAN"], line.Fields.Select(f => f.Name));
        Assert.Equal("\"Demir; Leyla\"", line.Text.Substring(line.Fields[1].Start, line.Fields[1].Length)); // quoted delimiter
    }

    [Theory]
    [InlineData("a,b,c", ',')]
    [InlineData("a;b;c", ';')]
    [InlineData("a\tb\tc", '\t')]
    [InlineData("a|b|c", '|')]
    public void DetectsDelimiter(string header, char expected) => Assert.Equal(expected, FieldExtractor.DetectDelimiter(header));

    [Fact]
    public void ExtraColumnsGetANumber()
    {
        var x = FieldExtractor.For("a.csv", "a,b");
        x.Context("a,b");
        Assert.Equal("column 3", x.Context("1,2,3").Fields[2].Name);
    }

    [Fact]
    public void JsonKeyValueAndXmlFields()
    {
        var fields = FieldExtractor.KeyValueFields("{\"email\":\"a@b.de\",\"n\":5} user=x <Iban>DE1</Iban>");
        Assert.Equal(["email", "n", "user", "Iban"], fields.Select(f => f.Name));
    }

    [Fact]
    public void LabelledLinesLikeYamlOrLetters()
    {
        var f = Assert.Single(FieldExtractor.KeyValueFields("Telefon: 069 8765 432"));
        Assert.Equal("Telefon", f.Name);
    }
}

public class ScannerTests
{
    private static ScanResult ScanSamples(ScanOptions? options = null) => new Scanner().Scan(T.SamplesDir, options ?? new ScanOptions
    {
        Ignore = IgnoreList.Parse(File.ReadAllText(Path.Combine(T.SamplesDir, ".piiscout-ignore"))),
        Exclude = ["README.md"],
    });

    [Fact]
    public void SamplesProduceTheExpectedDataMap()
    {
        var r = ScanSamples();
        Assert.Equal(6, r.FilesScanned);
        Assert.Equal(4, r.FilesWithData);
        Assert.Equal(Severity.Critical, r.Worst);
        Assert.True(r.Fails(Severity.High));

        var crm = r.Active.Where(m => m.Path == "crm-export.csv").ToDictionary(m => m.Field!);
        Assert.Equal(3, crm["E-Mail"].Count);            // the fourth is info@, a role mailbox
        Assert.Equal(4, crm["IBAN"].Count);
        Assert.Equal(2, crm["Konfession"].Count);
        Assert.Equal(Severity.Critical, crm["Konfession"].Severity);
        Assert.Equal(4, crm["Name"].Count);
    }

    [Fact]
    public void FixturesAreOnlyTestData()
    {
        var r = ScanSamples();
        var fixtures = r.Map.Where(m => m.Path == "fixtures/customers.json").ToList();
        Assert.NotEmpty(fixtures);
        Assert.All(fixtures, m => Assert.True(m.TestData));
        Assert.All(fixtures, m => Assert.Equal(Severity.Info, m.Severity));
    }

    [Fact]
    public void IgnoredFileIsSuppressedWithItsReason()
    {
        var r = ScanSamples();
        var impressum = r.Findings.Where(f => f.Path == "docs/impressum.md").ToList();
        Assert.NotEmpty(impressum);
        Assert.All(impressum, f => Assert.True(f.Suppressed));
        Assert.All(impressum, f => Assert.Contains("Impressum", f.SuppressedBecause));
    }

    [Fact]
    public void LogFindingsAndWhatIsNotReported()
    {
        var r = ScanSamples();
        var log = r.Findings.Where(f => f.Path == "logs/app.log").ToList();
        Assert.Contains(log, f => f.DetectorId == "PII-CARD" && f.Line == 3);
        Assert.Contains(log, f => f.DetectorId == "PII-IBAN" && f.Line == 4);
        Assert.DoesNotContain(log, f => f.Line == 2); // svc account, private IP
        Assert.DoesNotContain(log, f => f.Line == 6); // version number, private IP
    }

    [Fact]
    public void DistinctCountsUseFingerprints()
    {
        var r = new Scanner().ScanText("a.log", "a=erika@gmx.de\nb=erika@gmx.de\nc=ERIKA@gmx.de\nd=jonas@web.de\n");
        var emails = r.Map.Where(m => m.DetectorId == "PII-EMAIL").ToList();
        Assert.Equal(4, emails.Sum(m => m.Count));
        Assert.Equal(new[] { 1, 1, 1, 1 }, emails.Select(m => m.Distinct)); // one row per field
        var single = new Scanner().ScanText("a.log", "erika@gmx.de\nERIKA@gmx.de\njonas@web.de\n").Map.Single();
        Assert.Equal(3, single.Count);
        Assert.Equal(2, single.Distinct);
    }

    [Fact]
    public void FingerprintsAreStableOnlyWithAKey()
    {
        var a = new Scanner().ScanText("x", "erika@gmx.de", new ScanOptions { FingerprintKey = "k" }).Findings[0].Fingerprint;
        var b = new Scanner().ScanText("x", "erika@gmx.de", new ScanOptions { FingerprintKey = "k" }).Findings[0].Fingerprint;
        var c = new Scanner().ScanText("x", "erika@gmx.de", new ScanOptions { FingerprintKey = "other" }).Findings[0].Fingerprint;
        var random = new Scanner().ScanText("x", "erika@gmx.de");
        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
        Assert.False(random.StableFingerprints);
        Assert.Equal(16, a.Length);
    }

    [Fact]
    public void SamplesAreCappedButCountedInTheMap()
    {
        var text = string.Join('\n', Enumerable.Range(0, 60).Select(i => $"user{i}@gmx.de"));
        var r = new Scanner().ScanText("big.txt", text, new ScanOptions { MaxSamplesPerFile = 10 });
        Assert.Equal(10, r.Findings.Count);
        Assert.Equal(60, r.Map.Single().Count);
        Assert.Equal(60, r.Map.Single().Distinct);
    }

    [Fact]
    public void SkipsBinaryBuildFoldersAndLargeFiles()
    {
        using var dir = new TempDir();
        dir.Write("data/a.txt", "erika@gmx.de");
        dir.Write("bin/Debug/b.txt", "erika@gmx.de");
        dir.Write("node_modules/x/c.txt", "erika@gmx.de");
        dir.WriteBytes("blob.dat", [0x65, 0x00, 0x66, 0x00]);
        dir.Write("photo.png", "erika@gmx.de");
        dir.Write("large.log", new string('x', 2 * 1024 * 1024));

        var r = new Scanner().Scan(dir.Path, new ScanOptions { MaxFileBytes = 1024 * 1024 });
        Assert.Equal(1, r.FilesScanned);
        Assert.Equal("data/a.txt", r.Findings.Single().Path);
        Assert.Contains(r.Skipped, s => s.StartsWith("blob.dat: binary", StringComparison.Ordinal));
        Assert.Contains(r.Skipped, s => s.StartsWith("large.log: larger than", StringComparison.Ordinal));
    }

    [Fact]
    public void ExcludeByNameOrPath()
    {
        using var dir = new TempDir();
        dir.Write("samples/a.txt", "erika@gmx.de");
        dir.Write("src/samples/b.txt", "erika@gmx.de");
        dir.Write("src/keep/c.txt", "erika@gmx.de");
        Assert.Equal(["src/keep/c.txt"], new Scanner().Scan(dir.Path, new ScanOptions { Exclude = ["samples"] }).Findings.Select(f => f.Path));
        Assert.Equal(2, new Scanner().Scan(dir.Path, new ScanOptions { Exclude = ["src/samples"] }).FilesScanned);
    }

    [Fact]
    public void ReadsLatin1AndUtf16()
    {
        using var dir = new TempDir();
        dir.WriteBytes("excel.csv", Encoding.Latin1.GetBytes("Name;Ort\nJürgen Weiß;Gießen\n"));
        dir.WriteBytes("utf16.txt", Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("mail: erika@gmx.de")).ToArray());
        var r = new Scanner().Scan(dir.Path);
        Assert.Equal(2, r.FilesScanned);
        Assert.Contains(r.Findings, f => f.Path == "excel.csv" && f.Masked == "J. W.");
        Assert.Contains(r.Findings, f => f.Path == "utf16.txt" && f.DetectorId == "PII-EMAIL");
    }

    [Fact]
    public void ScanningASingleFile()
    {
        using var dir = new TempDir();
        var file = dir.Write("one.log", "ip=93.184.216.34");
        var r = new Scanner().Scan(file);
        Assert.Equal("one.log", r.Findings.Single().Path);
        Assert.Equal(Severity.Low, r.Worst);
        Assert.False(r.Fails(Severity.Medium));
        Assert.True(r.Fails(Severity.Low));
    }

    [Fact]
    public void MissingPathThrows() => Assert.Throws<FileNotFoundException>(() => new Scanner().Scan(Path.Combine(Path.GetTempPath(), "does-not-exist-" + Guid.NewGuid())));
}

public class IgnoreListTests
{
    private static readonly DateOnly Today = new(2026, 11, 7);

    [Fact]
    public void ParsesEntries()
    {
        var list = IgnoreList.Parse("""
            # comment
            tests/Fixtures/**   *          reason="synthetic"   expires=2027-01-31
            impressum.md        PII-PHONE  reason="published"
            """, Today);
        Assert.Equal(2, list.Entries.Count);
        Assert.Empty(list.Warnings);
        Assert.NotNull(list.Match("tests/Fixtures/deep/a.json", "PII-IBAN"));
        Assert.NotNull(list.Match("docs/impressum.md", "PII-PHONE"));
        Assert.Null(list.Match("docs/impressum.md", "PII-EMAIL"));  // only the named detector
        Assert.Null(list.Match("tests/other.json", "PII-IBAN"));
    }

    [Fact]
    public void EntryWithoutReasonIsNotApplied()
    {
        var list = IgnoreList.Parse("logs/**", Today);
        Assert.Empty(list.Entries);
        Assert.Contains("no reason", Assert.Single(list.Warnings));
    }

    [Fact]
    public void ExpiredEntryCountsAgain()
    {
        var list = IgnoreList.Parse("logs/** * reason=\"until rotation\" expires=2026-10-31", Today);
        Assert.Empty(list.Entries);
        Assert.Contains("expired on 2026-10-31", Assert.Single(list.Warnings));
    }

    [Fact]
    public void BadDateIsReported() =>
        Assert.Contains("yyyy-MM-dd", IgnoreList.Parse("a.txt * reason=\"x\" expires=31.12.2026", Today).Warnings.Single());

    [Theory]
    [InlineData("*.csv", "data/x.csv", true)]
    [InlineData("*.csv", "data/sub/x.csv", true)]   // no slash: file name anywhere
    [InlineData("data/*.csv", "data/sub/x.csv", false)]
    [InlineData("data/**/x.csv", "data/x.csv", true)]
    [InlineData("data/**/x.csv", "data/a/b/x.csv", true)]
    [InlineData("data/x?.csv", "data/x1.csv", true)]
    [InlineData("data/x?.csv", "data/x12.csv", false)]
    public void Globs(string glob, string path, bool matches) => Assert.Equal(matches, IgnoreList.GlobToRegex(glob).IsMatch(path));
}
