using System.Text;
using PiiScout.Core.Detectors;

namespace PiiScout.Core.Scanning;

public enum RedactionMode
{
    /// <summary>Replace each value with its masked form (DE89****3000).</summary>
    Mask,

    /// <summary>Replace each value with a keyed token ([IBAN:3f2a91c0]): the same value gets the same token, so a log stays analyzable.</summary>
    Pseudonymize,
}

public sealed record RedactionResult(string Text, IReadOnlyDictionary<string, int> Replaced)
{
    public int Total => Replaced.Values.Sum();
}

/// <summary>
/// Data minimization before sharing (Art. 5(1)(c) GDPR): a log or export goes to a vendor or into a ticket
/// without the personal data in it. Line endings and structure (CSV columns, JSON) are kept.
/// </summary>
public sealed class Redactor
{
    private readonly LineScanner scanner;

    public Redactor(LineScanner? scanner = null) => this.scanner = scanner ?? new LineScanner();

    /// <param name="name">File name, used to recognize CSV.</param>
    /// <param name="minimum">Redaction errs on the safe side: low-confidence hits are replaced too by default.</param>
    /// <param name="keepTestData">Leave published test values (4111..., example.com) as they are.</param>
    public RedactionResult Redact(string name, string text, RedactionMode mode = RedactionMode.Mask, string? key = null,
        Confidence minimum = Confidence.Low, bool keepTestData = true)
    {
        var fingerprints = Fingerprinter.Create(key);
        var counts = new Dictionary<string, int>();
        var output = new StringBuilder(text.Length);
        FieldExtractor? extractor = null;

        var position = 0;
        while (position < text.Length)
        {
            // Split by hand to keep each line's own ending (\n or \r\n)
            var end = text.IndexOf('\n', position);
            var lineEnd = end < 0 ? text.Length : end;
            var contentEnd = lineEnd > position && text[lineEnd - 1] == '\r' ? lineEnd - 1 : lineEnd;
            var line = text[position..contentEnd];
            extractor ??= FieldExtractor.For(name, line);

            output.Append(RedactLine(extractor.Context(line), mode, fingerprints, minimum, keepTestData, counts));
            output.Append(text, contentEnd, (end < 0 ? text.Length : end + 1) - contentEnd);
            position = end < 0 ? text.Length : end + 1;
        }
        return new RedactionResult(output.ToString(), counts);
    }

    private string RedactLine(LineContext line, RedactionMode mode, Fingerprinter fingerprints, Confidence minimum, bool keepTestData, Dictionary<string, int> counts)
    {
        var hits = scanner.Scan(line, minimum).Where(h => !(keepTestData && h.Hit.TestData)).ToList();
        if (hits.Count == 0) return line.Text;

        // A special-category field replaces the whole value, so the hits inside it are covered by it
        var art9 = hits.Where(h => h.Detector is SpecialCategoryFieldDetector).ToList();
        hits.RemoveAll(h => h.Detector is not SpecialCategoryFieldDetector
                            && art9.Any(a => h.Hit.Index >= a.Hit.Index && h.Hit.Index < a.Hit.Index + a.Hit.Length));

        var sb = new StringBuilder(line.Text);
        foreach (var (detector, hit) in hits.OrderByDescending(h => h.Hit.Index))
        {
            var (start, length, value) = (hit.Index, hit.Length, hit.Value);
            if (detector is SpecialCategoryFieldDetector)
            {
                // Keep surrounding quotes so CSV and JSON stay valid
                var raw = value;
                var lead = raw.Length - raw.TrimStart().TrimStart('"').Length;
                var trail = raw.Length - raw.TrimEnd().TrimEnd('"').Length;
                start += lead;
                length = Math.Max(0, length - lead - trail);
                value = line.Text.Substring(start, length);
            }
            var replacement = mode == RedactionMode.Pseudonymize
                ? $"[{Token(detector)}:{fingerprints.Of(detector, value)}]"
                : detector.Mask(value);
            sb.Remove(start, length).Insert(start, replacement);
            counts[detector.Id] = counts.GetValueOrDefault(detector.Id) + 1;
        }
        return sb.ToString();
    }

    internal static string Token(Detector d) => d.Id.Replace("PII-", "", StringComparison.Ordinal).Replace("DE-", "", StringComparison.Ordinal);
}
