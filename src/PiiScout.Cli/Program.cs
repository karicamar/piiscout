using System.Text;
using PiiScout.Core;
using PiiScout.Core.Detectors;
using PiiScout.Core.Policy;
using PiiScout.Core.Reporting;
using PiiScout.Core.Scanning;

Console.OutputEncoding = Encoding.UTF8;

if (args.Length > 0 && args[0] is "-h" or "--help" or "help")
    return Usage(0);
if (args.Length > 0 && args[0] == "--version")
{
    Console.WriteLine(ReportFormats.ToolVersion);
    return 0;
}
if (args.Length > 0 && args[0] == "detectors")
    return ListDetectors();
if (args.Length > 0 && args[0] == "redact")
    return Redact(args[1..]);

return Scan(args.Length > 0 && args[0] == "scan" ? args[1..] : args);

static int Scan(string[] args)
{
    var path = ".";
    var format = "console";
    string? output = null;
    string? ignoreFile = null;
    var failOn = Severity.High;
    var minConfidence = Confidence.Medium;
    var showTest = false;
    var exclude = new List<string>();
    long maxMb = 25;

    try
    {
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--format" or "-f": format = args[++i].ToLowerInvariant(); break;
                case "--output" or "-o": output = args[++i]; break;
                case "--ignore-file": ignoreFile = args[++i]; break;
                case "--fail-on":
                    var level = args[++i].ToLowerInvariant();
                    failOn = level == "none" ? (Severity)99 : Enum.Parse<Severity>(level, ignoreCase: true);
                    break;
                case "--min-confidence": minConfidence = Enum.Parse<Confidence>(args[++i], ignoreCase: true); break;
                case "--show-test-data": showTest = true; break;
                case "--exclude": exclude.Add(args[++i]); break;
                case "--max-file-size": maxMb = long.Parse(args[++i], System.Globalization.CultureInfo.InvariantCulture); break;
                default:
                    if (args[i].StartsWith('-')) { Console.Error.WriteLine($"Unknown option {args[i]}"); return Usage(2); }
                    path = args[i];
                    break;
            }
        }
    }
    catch (Exception ex) when (ex is IndexOutOfRangeException or ArgumentException or FormatException)
    {
        Console.Error.WriteLine("Invalid arguments: " + ex.Message);
        return Usage(2);
    }

    if (format is not ("console" or "json" or "markdown" or "md" or "sarif"))
    {
        Console.Error.WriteLine($"Unknown format {format}");
        return Usage(2);
    }
    if (!Directory.Exists(path) && !File.Exists(path))
    {
        Console.Error.WriteLine($"Not found: {path}");
        return 2;
    }

    var folder = Directory.Exists(path) ? path : Path.GetDirectoryName(Path.GetFullPath(path))!;
    var ignorePath = ignoreFile ?? Path.Combine(folder, ".piiscout-ignore");
    if (ignoreFile is not null && !File.Exists(ignoreFile))
    {
        Console.Error.WriteLine($"Ignore file not found: {ignoreFile}");
        return 2;
    }
    var ignore = File.Exists(ignorePath) ? IgnoreList.Parse(File.ReadAllText(ignorePath)) : IgnoreList.Empty;

    // Reports must not leak into the scanned folder and get scanned next time
    if (output is not null) exclude.Add(Path.GetFileName(output));

    var result = new Scanner().Scan(path, new ScanOptions
    {
        MinConfidence = minConfidence,
        Ignore = ignore,
        Exclude = exclude,
        MaxFileBytes = maxMb * 1024 * 1024,
        FingerprintKey = Environment.GetEnvironmentVariable("PIISCOUT_KEY"),
    });

    var text = format switch
    {
        "json" => ReportFormats.ToJson(result),
        "markdown" or "md" => ReportFormats.ToMarkdown(result),
        "sarif" => ReportFormats.ToSarif(result),
        _ => null,
    };

    if (text is null)
        ConsoleReport.Print(result, failOn, showTest);
    else if (output is not null)
    {
        File.WriteAllText(output, text);
        Console.Error.WriteLine($"Report written to {output}");
    }
    else
        Console.WriteLine(text);

    if (Environment.GetEnvironmentVariable("GITHUB_STEP_SUMMARY") is { Length: > 0 } summary)
        File.AppendAllText(summary, ReportFormats.ToMarkdown(result));

    return result.Fails(failOn) ? 1 : 0;
}

static int Redact(string[] args)
{
    string? input = null, output = null;
    var mode = RedactionMode.Mask;
    var inPlace = false;
    var keepTest = true;

    try
    {
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--output" or "-o": output = args[++i]; break;
                case "--pseudonymize": mode = RedactionMode.Pseudonymize; break;
                case "--in-place": inPlace = true; break;
                case "--include-test-data": keepTest = false; break;
                default:
                    if (args[i].StartsWith('-')) { Console.Error.WriteLine($"Unknown option {args[i]}"); return Usage(2); }
                    input = args[i];
                    break;
            }
        }
    }
    catch (IndexOutOfRangeException)
    {
        return Usage(2);
    }

    if (input is null || !File.Exists(input))
    {
        Console.Error.WriteLine(input is null ? "redact needs a file" : $"Not found: {input}");
        return 2;
    }
    var key = Environment.GetEnvironmentVariable("PIISCOUT_KEY");
    if (mode == RedactionMode.Pseudonymize && string.IsNullOrEmpty(key))
        Console.Error.WriteLine("Note: PIISCOUT_KEY is not set, tokens are random for this run (same value = same token only within this file).");

    var text = Scanner.Decode(File.ReadAllBytes(input), out var reason);
    if (text is null)
    {
        Console.Error.WriteLine($"{input}: {reason}");
        return 2;
    }

    var result = new Redactor().Redact(input, text, mode, key, keepTestData: keepTest);
    var target = inPlace ? input : output;
    if (target is null)
        Console.Write(result.Text);
    else
        File.WriteAllText(target, result.Text, new UTF8Encoding(false));

    var summary = result.Replaced.Count == 0 ? "nothing to redact"
        : string.Join(", ", result.Replaced.OrderByDescending(r => r.Value).Select(r => $"{r.Value} {DetectorCatalog.Get(r.Key).Name}"));
    Console.Error.WriteLine($"Redacted {result.Total} value(s): {summary}" + (target is null ? "" : $" → {target}"));
    return 0;
}

static int ListDetectors()
{
    foreach (var d in DetectorCatalog.All)
    {
        Console.WriteLine($"{d.Id,-16} {d.Severity,-9} {d.Name}  ({d.Legal})");
        Console.WriteLine($"{"",-27}{d.Description}");
        Console.WriteLine();
    }
    return 0;
}

static int Usage(int code)
{
    Console.WriteLine("""
        PiiScout: find personal data (GDPR / DSGVO) in files, logs, exports and test fixtures

        Usage:
          piiscout [scan] [folder | file] [options]       Scan and report (values are always masked)
          piiscout redact <file> [-o out | --in-place]    Write a copy with personal data masked
          piiscout detectors                              List what PiiScout detects

        Scan options:
          -f, --format <console|json|markdown|sarif>     Output format (default: console)
          -o, --output <file>                            Write the report to a file
              --fail-on <critical|high|medium|low|none>  Exit code 1 at this severity or above (default: high)
              --min-confidence <low|medium|high>         Report hits from this confidence (default: medium)
              --ignore-file <file>                       Accepted findings (default: .piiscout-ignore in the folder)
              --exclude <name or path>                   Skip a file or folder (repeatable)
              --max-file-size <MB>                       Skip larger files (default: 25)
              --show-test-data                           Also list test values and role mailboxes

        Redact options:
              --pseudonymize                             Stable tokens like [IBAN:3f2a91c0] instead of masks
              --include-test-data                        Also replace published test values

        Environment:
          PIISCOUT_KEY    Secret for fingerprints and pseudonyms, so they stay the same between runs

        Exit codes: 0 = OK, 1 = findings at or above --fail-on, 2 = error.

        Examples:
          piiscout samples
          piiscout . --exclude samples --format sarif -o piiscout.sarif
          piiscout redact logs/app.log --pseudonymize -o app.redacted.log
        """);
    return code;
}

static class ConsoleReport
{
    public static void Print(ScanResult r, Severity failOn, bool showTest)
    {
        Console.WriteLine();
        Write($"  PiiScout {ReportFormats.ToolVersion}", ConsoleColor.White);
        Console.WriteLine($"  {r.FilesScanned} file(s) scanned");
        Console.WriteLine();

        var active = r.Findings.Where(f => !f.Suppressed && (showTest || !f.TestData)).ToList();
        if (r.Active.Any() is false)
            Write("  ✓ No personal data found\n", ConsoleColor.Green);

        foreach (var file in active.GroupBy(f => f.Path))
        {
            var mapRows = r.Map.Where(m => m.Path == file.Key && !m.Suppressed && (showTest || !m.TestData)).ToList();
            var total = mapRows.Sum(m => m.Count);
            Write($"  {file.Key}", ConsoleColor.White);
            Write($"  {total} value(s)\n", ConsoleColor.DarkGray);
            foreach (var f in file)
            {
                Write($"    {Label(f.Severity),-9}", Color(f.Severity));
                Write($"{f.Line,5}:{f.Column,-4} ", ConsoleColor.DarkGray);
                Console.Write($"{f.Name,-34} {f.Masked}");
                var extra = string.Join(", ", new[] { f.Field is null ? null : $"field '{f.Field}'", f.Note, f.Confidence == Confidence.High ? null : $"{f.Confidence.ToString().ToLowerInvariant()} confidence" }.Where(x => x is not null));
                Write(extra.Length > 0 ? $"  ({extra})\n" : "\n", ConsoleColor.DarkGray);
            }
            var shown = file.Count();
            if (total > shown)
                Write($"    … and {total - shown} more (see --format json or markdown for the full data map)\n", ConsoleColor.DarkGray);
            Console.WriteLine();
        }

        var suppressed = r.Map.Where(m => m.Suppressed).ToList();
        if (suppressed.Count > 0)
            Write($"  accepted in .piiscout-ignore: {suppressed.Sum(m => m.Count)} value(s) in {suppressed.Select(m => m.Path).Distinct().Count()} file(s)\n", ConsoleColor.DarkGray);
        var test = r.Map.Where(m => m.TestData && !m.Suppressed).Sum(m => m.Count);
        if (test > 0 && !showTest)
            Write($"  {test} test value(s) / role mailbox(es) not counted (--show-test-data to list them)\n", ConsoleColor.DarkGray);
        foreach (var s in r.Skipped)
            Write($"  - {s}\n", ConsoleColor.DarkGray);
        foreach (var w in r.Warnings)
            Write($"  ! {w}\n", ConsoleColor.Yellow);

        var rows = r.Active.ToList();
        if (rows.Count > 0)
        {
            var bySeverity = string.Join(", ", new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low }
                .Select(s => (s, n: rows.Where(m => m.Severity == s).Sum(m => m.Count))).Where(x => x.n > 0)
                .Select(x => $"{x.n} {x.s.ToString().ToLowerInvariant()}"));
            Console.WriteLine();
            var fails = r.Fails(failOn);
            Write($"  {rows.Sum(m => m.Count)} value(s) of personal data in {r.FilesWithData} file(s): {bySeverity}."
                  + (fails ? $" Failing: --fail-on {failOn.ToString().ToLowerInvariant()}.\n" : "\n"), fails ? ConsoleColor.Red : ConsoleColor.Yellow);
        }
        Console.WriteLine();
    }

    private static string Label(Severity s) => s.ToString().ToUpperInvariant();

    private static ConsoleColor Color(Severity s) => s switch
    {
        Severity.Critical => ConsoleColor.Magenta,
        Severity.High => ConsoleColor.Red,
        Severity.Medium => ConsoleColor.DarkYellow,
        Severity.Low => ConsoleColor.Yellow,
        _ => ConsoleColor.Gray,
    };

    private static void Write(string text, ConsoleColor color)
    {
        var old = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ForegroundColor = old;
    }
}
