using System.Text.RegularExpressions;
using PiiScout.Core.Detectors;

namespace PiiScout.Core.Scanning;

/// <summary>
/// Turns lines into <see cref="LineContext"/>s with named fields, so "4111..." in a column called "iban"
/// or a JSON property "steuer_id" gets its context even when no keyword is in the text itself.
/// </summary>
public sealed partial class FieldExtractor
{
    private readonly char? delimiter;
    private string[]? header;

    private FieldExtractor(char? delimiter) => this.delimiter = delimiter;

    /// <summary>CSV/TSV mode when the file looks tabular (by extension, or a header line with a consistent delimiter).</summary>
    public static FieldExtractor For(string path, string? firstLine)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        if (ext is ".tsv" or ".tab") return new FieldExtractor('\t');
        if (ext == ".csv" && firstLine is not null) return new FieldExtractor(DetectDelimiter(firstLine) ?? ',');
        return new FieldExtractor(null);
    }

    public bool IsTabular => delimiter is not null;
    public IReadOnlyList<string>? Header => header;

    internal static char? DetectDelimiter(string line)
    {
        char? best = null;
        var bestCount = 0;
        foreach (var c in new[] { ';', ',', '\t', '|' })
        {
            var n = SplitCsv(line, c).Count;
            if (n > bestCount && n > 1) { best = c; bestCount = n; }
        }
        return best;
    }

    public LineContext Context(string line)
    {
        if (delimiter is { } d)
        {
            var cells = SplitCsv(line, d);
            if (header is null)
            {
                header = cells.Select(c => Unquote(line.Substring(c.Start, c.Length))).ToArray();
                // The header names themselves are not data, but give them as fields so the header line has context too
                return new LineContext(line);
            }
            var fields = new List<Field>(cells.Count);
            for (var i = 0; i < cells.Count; i++)
                fields.Add(new Field(i < header.Length ? header[i] : $"column {i + 1}", cells[i].Start, cells[i].Length));
            return new LineContext(line, fields) { Tabular = true };
        }

        return new LineContext(line, KeyValueFields(line));
    }

    /// <summary>Cells of one CSV line as (start, length) of the raw text, quotes respected.</summary>
    internal static List<(int Start, int Length)> SplitCsv(string line, char delimiter)
    {
        var cells = new List<(int, int)>();
        var start = 0;
        var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (c == '"') quoted = !quoted;
            else if (c == delimiter && !quoted)
            {
                cells.Add((start, i - start));
                start = i + 1;
            }
        }
        cells.Add((start, line.Length - start));
        return cells;
    }

    private static string Unquote(string s) => s.Trim().Trim('"').Trim();

    [GeneratedRegex(@"""([^""\\]{1,64})""\s*:\s*(?:""((?:[^""\\]|\\.)*)""|([^,}\]\s]+))")]
    private static partial Regex JsonProperty();

    [GeneratedRegex(@"(?<![\w.\-])([A-Za-z_][\w.\-]{0,40})=(?:""([^""]*)""|([^\s,;&""]+))")]
    private static partial Regex KeyEqualsValue();

    [GeneratedRegex(@"<([A-Za-z][\w.\-:]{0,40})(?:\s[^>]*)?>([^<]{1,200})</\1>")]
    private static partial Regex XmlElement();

    [GeneratedRegex(@"^\s*-?\s*([A-Za-zÄÖÜäöüß][\wÄÖÜäöüß.\- ]{0,40}?)\s?:\s+(\S.*?)\s*$")]
    private static partial Regex Labelled();

    internal static List<Field> KeyValueFields(string line)
    {
        var fields = new List<Field>();

        foreach (Match m in JsonProperty().Matches(line))
        {
            var value = m.Groups[2].Success ? m.Groups[2] : m.Groups[3];
            fields.Add(new Field(m.Groups[1].Value, value.Index, value.Length));
        }
        foreach (Match m in KeyEqualsValue().Matches(line))
        {
            var value = m.Groups[2].Success ? m.Groups[2] : m.Groups[3];
            if (!Overlaps(fields, value.Index)) fields.Add(new Field(m.Groups[1].Value, value.Index, value.Length));
        }
        foreach (Match m in XmlElement().Matches(line))
            if (!Overlaps(fields, m.Groups[2].Index)) fields.Add(new Field(m.Groups[1].Value, m.Groups[2].Index, m.Groups[2].Length));

        // "Telefon: 069 ..." and YAML "email: x" (only when nothing more specific was found on the line)
        if (fields.Count == 0 && Labelled().Match(line) is { Success: true } l)
            fields.Add(new Field(l.Groups[1].Value.Trim(), l.Groups[2].Index, l.Groups[2].Length));

        return fields;
    }

    private static bool Overlaps(List<Field> fields, int index) => fields.Any(f => index >= f.Start && index < f.End);
}
