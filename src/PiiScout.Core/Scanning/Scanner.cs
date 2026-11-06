using System.Text;
using PiiScout.Core.Detectors;
using PiiScout.Core.Policy;

namespace PiiScout.Core.Scanning;

public sealed record ScanOptions
{
    public Confidence MinConfidence { get; init; } = Confidence.Medium;
    public IgnoreList Ignore { get; init; } = IgnoreList.Empty;
    public IReadOnlyList<string> Exclude { get; init; } = [];
    public long MaxFileBytes { get; init; } = 25 * 1024 * 1024;

    /// <summary>Findings listed per file and detector; everything beyond is still counted in the data map.</summary>
    public int MaxSamplesPerFile { get; init; } = 25;

    /// <summary>Secret for fingerprints (env PIISCOUT_KEY). Without it fingerprints are random per run.</summary>
    public string? FingerprintKey { get; init; }
}

/// <summary>One row of the data map: which kind of personal data sits where, how often, how many distinct values.</summary>
public sealed record DataMapEntry(string Path, string? Field, string DetectorId, string Name, Category Category, Severity Severity, int Count, int Distinct, bool TestData, bool Suppressed);

public sealed class ScanResult
{
    public required string Root { get; init; }
    public required IReadOnlyList<Finding> Findings { get; init; }
    public required IReadOnlyList<DataMapEntry> Map { get; init; }
    public required int FilesScanned { get; init; }
    public required IReadOnlyList<string> Skipped { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public required bool StableFingerprints { get; init; }

    public IEnumerable<DataMapEntry> Active => Map.Where(m => !m.Suppressed && !m.TestData);

    public Severity? Worst => Active.Select(m => (Severity?)m.Severity).Max();

    public bool Fails(Severity threshold) => Active.Any(m => m.Severity >= threshold);

    public int FilesWithData => Active.Select(m => m.Path).Distinct().Count();
}

public sealed class Scanner
{
    // Folders that hold build output or third-party code, not your data
    private static readonly HashSet<string> SkippedFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git", ".vs", ".idea", ".vscode", "bin", "obj", "node_modules", "packages", ".terraform", "__pycache__", "TestResults",
    };

    private static readonly HashSet<string> BinaryExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svgz", ".pdf", ".zip", ".gz", ".tgz", ".7z", ".rar",
        ".dll", ".exe", ".pdb", ".so", ".dylib", ".nupkg", ".snupkg", ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".mp3", ".mp4", ".mov", ".avi", ".db", ".sqlite", ".mdf", ".ldf", ".pfx", ".p12", ".class", ".jar", ".docx", ".xlsx", ".pptx",
    };

    private readonly LineScanner lines;

    public Scanner(LineScanner? lines = null) => this.lines = lines ?? new LineScanner();

    public ScanResult Scan(string path, ScanOptions? options = null)
    {
        options ??= new ScanOptions();
        var fingerprints = Fingerprinter.Create(options.FingerprintKey);
        var root = Directory.Exists(path) ? Path.GetFullPath(path) : Path.GetDirectoryName(Path.GetFullPath(path))!;
        IEnumerable<string> files = Directory.Exists(path) ? Enumerate(root, options.Exclude)
            : File.Exists(path) ? [Path.GetFullPath(path)]
            : throw new FileNotFoundException($"Not found: {path}");

        var findings = new List<Finding>();
        var map = new List<DataMapEntry>();
        var skipped = new List<string>();
        var warnings = new List<string>(options.Ignore.Warnings);
        var scanned = 0;

        foreach (var file in files)
        {
            var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            if (Read(file, options.MaxFileBytes, out var reason) is not { } text)
            {
                if (reason is not null) skipped.Add($"{relative}: {reason}");
                continue;
            }
            scanned++;
            ScanText(relative, text, options, fingerprints, findings, map);
        }

        if (!fingerprints.Stable && map.Count > 0)
            warnings.Add("Fingerprints use a random key (set PIISCOUT_KEY to compare them between runs).");

        return new ScanResult
        {
            Root = root,
            Findings = findings,
            Map = map,
            FilesScanned = scanned,
            Skipped = skipped,
            Warnings = warnings,
            StableFingerprints = fingerprints.Stable,
        };
    }

    /// <summary>Scans text that is already in memory (also used by tests and by the redact command's summary).</summary>
    public ScanResult ScanText(string name, string text, ScanOptions? options = null)
    {
        options ??= new ScanOptions();
        var fingerprints = Fingerprinter.Create(options.FingerprintKey);
        var findings = new List<Finding>();
        var map = new List<DataMapEntry>();
        ScanText(name, text, options, fingerprints, findings, map);
        return new ScanResult
        {
            Root = ".", Findings = findings, Map = map, FilesScanned = 1, Skipped = [], Warnings = options.Ignore.Warnings,
            StableFingerprints = fingerprints.Stable,
        };
    }

    private void ScanText(string relative, string text, ScanOptions options, Fingerprinter fingerprints, List<Finding> findings, List<DataMapEntry> map)
    {
        // Aggregate per (field, detector, test data) for the data map; keep a few samples per detector as findings
        var groups = new Dictionary<(string? Field, string Detector, bool Test), (int Count, HashSet<string> Distinct)>();
        var samples = new Dictionary<string, int>();
        var allLines = SplitLines(text);
        var extractor = FieldExtractor.For(relative, allLines.Count > 0 ? allLines[0] : null);

        for (var n = 0; n < allLines.Count; n++)
        {
            var line = allLines[n];
            if (line.Length == 0) continue;
            var context = extractor.Context(line);
            foreach (var (detector, hit) in lines.Scan(context, options.MinConfidence))
            {
                var field = context.FieldAt(hit.Index)?.Name;
                var fingerprint = fingerprints.Of(detector, hit.Value);
                var key = (field, detector.Id, hit.TestData);
                if (!groups.TryGetValue(key, out var g)) g = (0, []);
                g.Distinct.Add(fingerprint);
                groups[key] = (g.Count + 1, g.Distinct);

                samples.TryGetValue(detector.Id, out var shown);
                if (shown >= options.MaxSamplesPerFile) continue;
                samples[detector.Id] = shown + 1;

                var ignored = options.Ignore.Match(relative, detector.Id);
                findings.Add(new Finding(
                    detector.Id, detector.Name, detector.Category,
                    hit.TestData ? Severity.Info : detector.Severity, hit.Confidence,
                    relative, n + 1, hit.Index + 1, detector.Mask(hit.Value), fingerprint, field, hit.TestData, hit.Note)
                {
                    Suppressed = ignored is not null,
                    SuppressedBecause = ignored?.Reason,
                });
            }
        }

        foreach (var ((field, id, test), (count, distinct)) in groups.OrderBy(g => g.Key.Field).ThenBy(g => g.Key.Detector))
        {
            var d = DetectorCatalog.Get(id);
            map.Add(new DataMapEntry(relative, field, id, d.Name, d.Category, test ? Severity.Info : d.Severity, count, distinct.Count, test,
                options.Ignore.Match(relative, id) is not null));
        }
    }

    internal static List<string> SplitLines(string text)
    {
        var result = new List<string>();
        using var reader = new StringReader(text);
        while (reader.ReadLine() is { } line) result.Add(line);
        return result;
    }

    private static IEnumerable<string> Enumerate(string root, IReadOnlyList<string> exclude)
    {
        var excluded = exclude.Select(e => e.Replace('\\', '/').Trim('/')).ToList();
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            IEnumerable<string> entries;
            try { entries = Directory.EnumerateFileSystemEntries(dir).Order(StringComparer.Ordinal).ToList(); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var entry in entries.Reverse())
            {
                var relative = Path.GetRelativePath(root, entry).Replace('\\', '/');
                var name = Path.GetFileName(entry);
                if (excluded.Any(e => e.Contains('/') ? relative.Equals(e, StringComparison.OrdinalIgnoreCase) || relative.StartsWith(e + "/", StringComparison.OrdinalIgnoreCase)
                                                      : name.Equals(e, StringComparison.OrdinalIgnoreCase)))
                    continue;
                if (Directory.Exists(entry))
                {
                    if (!SkippedFolders.Contains(name)) stack.Push(entry);
                }
                else if (name != ".piiscout-ignore")
                    yield return entry;
            }
        }
    }

    /// <summary>Reads a text file (UTF-8 with or without BOM, UTF-16 with BOM, Windows-1252/Latin-1 fallback). Null for binary or too large.</summary>
    internal static string? Read(string file, long maxBytes, out string? reason)
    {
        reason = null;
        if (BinaryExtensions.Contains(Path.GetExtension(file))) return null;
        var info = new FileInfo(file);
        if (info.Length > maxBytes)
        {
            reason = $"larger than {maxBytes / 1024 / 1024} MB, skipped";
            return null;
        }
        var bytes = File.ReadAllBytes(file);
        return Decode(bytes, out reason);
    }

    public static string? Decode(byte[] bytes, out string? reason)
    {
        reason = null;
        if (bytes.Length >= 2 && ((bytes[0] == 0xFF && bytes[1] == 0xFE) || (bytes[0] == 0xFE && bytes[1] == 0xFF)))
            return new StreamReader(new MemoryStream(bytes), detectEncodingFromByteOrderMarks: true).ReadToEnd();

        var probe = Math.Min(bytes.Length, 8192);
        for (var i = 0; i < probe; i++)
            if (bytes[i] == 0)
            {
                reason = "binary file, skipped";
                return null;
            }

        try
        {
            var utf8 = new UTF8Encoding(false, throwOnInvalidBytes: true);
            var text = utf8.GetString(bytes);
            return text.Length > 0 && text[0] == '﻿' ? text[1..] : text;
        }
        catch (DecoderFallbackException)
        {
            return Encoding.Latin1.GetString(bytes); // older German exports (Excel CSV) are often Windows-1252
        }
    }
}
