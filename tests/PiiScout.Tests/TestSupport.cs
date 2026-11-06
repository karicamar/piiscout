using PiiScout.Core;
using PiiScout.Core.Detectors;
using PiiScout.Core.Scanning;

namespace PiiScout.Tests;

internal static class T
{
    /// <summary>Hits of one detector on a plain line (fields extracted like the scanner does for non-CSV files).</summary>
    public static List<Detection> Hits(Detector d, string line) =>
        d.Find(new LineContext(line, FieldExtractor.KeyValueFields(line))).ToList();

    public static Detection Single(Detector d, string line) => Assert.Single(Hits(d, line));

    /// <summary>What the full scanner reports for this line (all detectors, overlaps resolved).</summary>
    public static List<string> Ids(string line, Confidence min = Confidence.Low) =>
        new LineScanner().Scan(new LineContext(line, FieldExtractor.KeyValueFields(line)), min).Select(h => h.Detector.Id).ToList();

    public static string SamplesDir
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "samples")))
                dir = dir.Parent;
            return Path.Combine(dir?.FullName ?? throw new DirectoryNotFoundException("samples"), "samples");
        }
    }
}

/// <summary>A temporary folder that is deleted after the test.</summary>
internal sealed class TempDir : IDisposable
{
    public TempDir() => Directory.CreateDirectory(Path);

    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "piiscout-" + Guid.NewGuid().ToString("N")[..8]);

    public string Write(string relative, string content)
    {
        var full = System.IO.Path.Combine(Path, relative);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
        File.WriteAllText(full, content);
        return full;
    }

    public string WriteBytes(string relative, byte[] content)
    {
        var full = System.IO.Path.Combine(Path, relative);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, content);
        return full;
    }

    public void Dispose()
    {
        try { Directory.Delete(Path, recursive: true); } catch (IOException) { }
    }
}
