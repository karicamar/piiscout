using System.Security.Cryptography;
using System.Text;
using PiiScout.Core.Detectors;

namespace PiiScout.Core.Scanning;

/// <summary>Runs all detectors on one line and resolves overlaps: the more severe, then the longer hit wins.</summary>
public sealed class LineScanner
{
    private readonly IReadOnlyList<Detector> detectors;

    public LineScanner(IReadOnlyList<Detector>? detectors = null) => this.detectors = detectors ?? DetectorCatalog.All;

    public IReadOnlyList<(Detector Detector, Detection Hit)> Scan(LineContext line, Confidence minimum)
    {
        var all = new List<(Detector, Detection)>();
        foreach (var d in detectors)
            foreach (var hit in d.Find(line))
                if (hit.Confidence >= minimum)
                    all.Add((d, hit));
        if (all.Count <= 1) return all;

        // A tax id inside an IBAN, a phone number inside a card number: keep only the strongest explanation of each span
        all.Sort((a, b) =>
        {
            var bySeverity = b.Item1.Severity.CompareTo(a.Item1.Severity);
            if (bySeverity != 0) return bySeverity;
            var byLength = b.Item2.Length.CompareTo(a.Item2.Length);
            return byLength != 0 ? byLength : a.Item2.Index.CompareTo(b.Item2.Index);
        });
        var kept = new List<(Detector Detector, Detection Hit)>();
        foreach (var candidate in all)
        {
            var (s, e) = (candidate.Item2.Index, candidate.Item2.Index + candidate.Item2.Length);
            // A special-category field is about the column, not the characters: other hits inside it stay visible
            var overlaps = kept.Any(k =>
                k.Detector is not SpecialCategoryFieldDetector && candidate.Item1 is not SpecialCategoryFieldDetector
                && s < k.Hit.Index + k.Hit.Length && k.Hit.Index < e);
            if (!overlaps) kept.Add(candidate);
        }
        kept.Sort((a, b) => a.Hit.Index.CompareTo(b.Hit.Index));
        return kept;
    }
}

/// <summary>
/// Keyed fingerprints (HMAC-SHA256) of values: lets reports count distinct values and correlate them across files
/// without storing the value. Without a fixed key a random one is used, so fingerprints are only comparable within one run.
/// </summary>
public sealed class Fingerprinter
{
    private readonly byte[] key;

    public Fingerprinter(string? secret = null) =>
        key = secret is { Length: > 0 } ? Encoding.UTF8.GetBytes(secret) : RandomNumberGenerator.GetBytes(32);

    public bool Stable { get; private init; }

    public static Fingerprinter Create(string? secret) => new(secret) { Stable = secret is { Length: > 0 } };

    public string Of(Detector detector, string value)
    {
        var hash = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(detector.Id + "\n" + detector.Normalize(value)));
        return Convert.ToHexStringLower(hash.AsSpan(0, 8));
    }
}
