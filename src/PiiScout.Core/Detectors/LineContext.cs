namespace PiiScout.Core.Detectors;

/// <summary>A named value inside a line: a CSV column, a JSON property, or key=value in a log line.</summary>
public sealed record Field(string Name, int Start, int Length)
{
    public int End => Start + Length;
}

/// <summary>One line of text plus what we know about its structure. Detectors use it for context words.</summary>
public sealed class LineContext
{
    private const int Window = 48;
    private string? lowered;

    public LineContext(string text, IReadOnlyList<Field>? fields = null)
    {
        Text = text;
        Fields = fields ?? [];
    }

    public string Text { get; }
    public IReadOnlyList<Field> Fields { get; }

    /// <summary>True for CSV/TSV rows, where field names come from the header line.</summary>
    public bool Tabular { get; init; }

    private string Lowered => lowered ??= Text.ToLowerInvariant();

    /// <summary>The field whose value contains this position, if any.</summary>
    public Field? FieldAt(int index)
    {
        foreach (var f in Fields)
            if (index >= f.Start && index < Math.Max(f.End, f.Start + 1))
                return f;
        return null;
    }

    /// <summary>
    /// True when a keyword appears in the field name of the value, or in the text just before it.
    /// Keywords are matched lower-case; field names are compared without "_", "-" and spaces.
    /// </summary>
    public bool HasContext(int index, IReadOnlyList<string> keywords)
    {
        if (FieldAt(index) is { } field)
        {
            var name = Normalize(field.Name);
            foreach (var k in keywords)
                if (name.Contains(Normalize(k), StringComparison.Ordinal))
                    return true;
        }

        var start = Math.Max(0, index - Window);
        var before = Lowered.AsSpan(start, index - start);
        foreach (var k in keywords)
            if (before.Contains(k, StringComparison.Ordinal))
                return true;
        return false;
    }

    internal static string Normalize(string name)
    {
        Span<char> buffer = stackalloc char[Math.Min(name.Length, 128)];
        var n = 0;
        foreach (var c in name)
        {
            if (n == buffer.Length) break;
            if (c is '_' or '-' or ' ' or '.') continue;
            buffer[n++] = char.ToLowerInvariant(c);
        }
        return new string(buffer[..n]);
    }
}
