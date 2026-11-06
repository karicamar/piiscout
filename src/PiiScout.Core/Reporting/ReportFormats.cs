using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using PiiScout.Core.Detectors;
using PiiScout.Core.Scanning;

namespace PiiScout.Core.Reporting;

public static class ReportFormats
{
    public const string ToolVersion = "1.0.0";
    public const string InformationUri = "https://github.com/karicamar/piiscout";

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string ToJson(ScanResult r)
    {
        var report = new
        {
            tool = "PiiScout",
            version = ToolVersion,
            filesScanned = r.FilesScanned,
            filesWithPersonalData = r.FilesWithData,
            worst = r.Worst,
            stableFingerprints = r.StableFingerprints,
            dataMap = r.Map,
            findings = r.Findings,
            skipped = r.Skipped,
            warnings = r.Warnings,
        };
        return JsonSerializer.Serialize(report, Json);
    }

    /// <summary>
    /// Markdown for the CI summary and for the data protection officer: the data map is the raw material for the
    /// records of processing activities (Art. 30 GDPR) and for answering "where do we store X?" (Art. 15, 17).
    /// </summary>
    public static string ToMarkdown(ScanResult r)
    {
        var sb = new StringBuilder();
        sb.AppendLine("## PiiScout: personal data report").AppendLine();
        var active = r.Active.ToList();
        if (active.Count == 0)
            sb.AppendLine($"✅ No personal data found in {r.FilesScanned} file(s).").AppendLine();
        else
        {
            sb.AppendLine($"**{active.Sum(m => m.Count)} values** in **{r.FilesWithData} of {r.FilesScanned} files**. Worst: **{r.Worst}**.").AppendLine();
            sb.AppendLine("| Category | Values | Files |").AppendLine("|---|---:|---:|");
            foreach (var g in active.GroupBy(m => m.Category).OrderByDescending(g => g.Max(m => m.Severity)))
                sb.AppendLine($"| {CategoryInfo.Label(g.Key)} | {g.Sum(m => m.Count)} | {g.Select(m => m.Path).Distinct().Count()} |");
            sb.AppendLine();

            sb.AppendLine("### Data map").AppendLine();
            sb.AppendLine("| Severity | File | Field | Data | Values | Distinct |").AppendLine("|---|---|---|---|---:|---:|");
            foreach (var m in active.OrderByDescending(m => m.Severity).ThenBy(m => m.Path, StringComparer.Ordinal).ThenBy(m => m.Field))
                sb.AppendLine($"| {Icon(m.Severity)} {m.Severity} | `{m.Path}` | {(m.Field is null ? "–" : $"`{Escape(m.Field)}`")} | {m.Name} | {m.Count} | {m.Distinct} |");
            sb.AppendLine();
        }

        var suppressed = r.Map.Where(m => m.Suppressed).ToList();
        var test = r.Map.Where(m => m.TestData && !m.Suppressed).ToList();
        if (suppressed.Count > 0)
            sb.AppendLine($"Accepted in `.piiscout-ignore`: {suppressed.Sum(m => m.Count)} value(s) in {suppressed.Select(m => m.Path).Distinct().Count()} file(s).").AppendLine();
        if (test.Count > 0)
            sb.AppendLine($"Test data and role mailboxes (not counted): {test.Sum(m => m.Count)} value(s).").AppendLine();

        if (active.Any(m => m.Category == Category.SpecialCategory))
            sb.AppendLine("> ⚠️ **Art. 9 GDPR:** special categories (health, religion, union membership, …) may only be processed under one of the exceptions of Art. 9(2). Check the legal basis and who can read these files.").AppendLine();
        if (active.Count > 0)
            sb.AppendLine("> 🇩🇪 Die Datenkarte ist eine Grundlage für das Verzeichnis von Verarbeitungstätigkeiten (Art. 30 DSGVO) und für Auskunfts- und Löschanfragen (Art. 15, 17 DSGVO). Werte werden nie im Klartext ausgegeben.").AppendLine();

        foreach (var w in r.Warnings.Concat(r.Skipped))
            sb.AppendLine($"- {w}");
        return sb.ToString();
    }

    private static string Icon(Severity s) => s switch
    {
        Severity.Critical => "🟣",
        Severity.High => "🔴",
        Severity.Medium => "🟠",
        Severity.Low => "🟡",
        _ => "⚪",
    };

    private static string Escape(string s) => s.Replace("|", "\\|").Replace("`", "'");

    /// <summary>SARIF 2.1.0 for GitHub Code Scanning. Locations are relative paths; messages contain only masked values.</summary>
    public static string ToSarif(ScanResult r)
    {
        var used = r.Findings.Select(f => f.DetectorId).Distinct().ToHashSet();
        var rules = DetectorCatalog.All.Where(d => used.Contains(d.Id)).ToList();

        var results = new JsonArray();
        foreach (var f in r.Findings.Where(f => !f.TestData))
        {
            var message = $"{f.Name} {f.Masked}" + (f.Field is null ? "" : $" in field '{f.Field}'") + (f.Note is null ? "" : $" ({f.Note})");
            var result = new JsonObject
            {
                ["ruleId"] = f.DetectorId,
                ["ruleIndex"] = rules.FindIndex(d => d.Id == f.DetectorId),
                ["level"] = f.Severity switch { Severity.Critical or Severity.High => "error", Severity.Medium => "warning", _ => "note" },
                ["message"] = new JsonObject { ["text"] = message },
                ["locations"] = new JsonArray(new JsonObject
                {
                    ["physicalLocation"] = new JsonObject
                    {
                        ["artifactLocation"] = new JsonObject { ["uri"] = f.Path },
                        ["region"] = new JsonObject { ["startLine"] = f.Line, ["startColumn"] = f.Column },
                    },
                }),
                // The keyed fingerprint lets Code Scanning track the same value across commits without knowing it
                ["partialFingerprints"] = new JsonObject { ["piiValue/v1"] = f.Fingerprint },
                ["properties"] = new JsonObject { ["confidence"] = f.Confidence.ToString().ToLowerInvariant(), ["category"] = f.Category.ToString() },
            };
            if (f.Suppressed)
                result["suppressions"] = new JsonArray(new JsonObject { ["kind"] = "external", ["justification"] = f.SuppressedBecause });
            results.Add(result);
        }

        var sarif = new JsonObject
        {
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["version"] = "2.1.0",
            ["runs"] = new JsonArray(new JsonObject
            {
                ["tool"] = new JsonObject
                {
                    ["driver"] = new JsonObject
                    {
                        ["name"] = "PiiScout",
                        ["version"] = ToolVersion,
                        ["informationUri"] = InformationUri,
                        ["rules"] = new JsonArray(rules.Select(d => (JsonNode)new JsonObject
                        {
                            ["id"] = d.Id,
                            ["name"] = d.Name.Replace(" ", "", StringComparison.Ordinal).Replace("(", "").Replace(")", "").Replace("-", ""),
                            ["shortDescription"] = new JsonObject { ["text"] = d.Name },
                            ["fullDescription"] = new JsonObject { ["text"] = d.Description },
                            ["help"] = new JsonObject { ["text"] = $"{d.Description} Legal reference: {d.Legal}." },
                            ["properties"] = new JsonObject
                            {
                                ["security-severity"] = d.Severity switch { Severity.Critical => "9.0", Severity.High => "7.5", Severity.Medium => "5.0", _ => "3.0" },
                                ["tags"] = new JsonArray("privacy", "gdpr", d.Category.ToString()),
                            },
                        }).ToArray()),
                    },
                },
                ["results"] = results,
            }),
        };
        return sarif.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }
}
