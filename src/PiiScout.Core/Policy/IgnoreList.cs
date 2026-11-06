using System.Globalization;
using System.Text.RegularExpressions;

namespace PiiScout.Core.Policy;

/// <summary>
/// Accepted findings, one per line in <c>.piiscout-ignore</c>:
/// <code>
/// tests/Fixtures/**        *              reason="synthetic customers, generated" expires=2027-06-30
/// docs/impressum.md        PII-PHONE      reason="published company number"
/// </code>
/// Every entry needs a reason. An expired entry stops suppressing, so "temporary" stays temporary.
/// </summary>
public sealed partial class IgnoreList
{
    public static IgnoreList Empty { get; } = new([], []);

    private IgnoreList(IReadOnlyList<Entry> entries, IReadOnlyList<string> warnings)
    {
        Entries = entries;
        Warnings = warnings;
    }

    public IReadOnlyList<Entry> Entries { get; }
    public IReadOnlyList<string> Warnings { get; }

    public sealed record Entry(string Glob, string Detector, string Reason, DateOnly? Expires, int Line)
    {
        internal Regex Pattern { get; } = GlobToRegex(Glob);
    }

    [GeneratedRegex(@"^(?<glob>\S+)(?:\s+(?<det>(?!reason=|expires=)\S+))?(?<rest>.*)$")]
    private static partial Regex LinePattern();

    [GeneratedRegex(@"reason=""(?<r>[^""]*)""|expires=(?<e>\S+)")]
    private static partial Regex Attributes();

    public static IgnoreList Parse(string text, DateOnly? today = null)
    {
        var now = today ?? DateOnly.FromDateTime(DateTime.UtcNow);
        var entries = new List<Entry>();
        var warnings = new List<string>();
        var lines = text.Split('\n');
        for (var n = 0; n < lines.Length; n++)
        {
            var raw = lines[n].Trim();
            if (raw.Length == 0 || raw.StartsWith('#')) continue;
            var m = LinePattern().Match(raw);
            var glob = m.Groups["glob"].Value.Replace('\\', '/');
            var detector = m.Groups["det"].Success ? m.Groups["det"].Value : "*";
            string? reason = null;
            DateOnly? expires = null;
            foreach (Match a in Attributes().Matches(m.Groups["rest"].Value))
            {
                if (a.Groups["r"].Success) reason = a.Groups["r"].Value.Trim();
                else if (DateOnly.TryParseExact(a.Groups["e"].Value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)) expires = d;
                else warnings.Add($".piiscout-ignore line {n + 1}: expires must be yyyy-MM-dd");
            }

            if (string.IsNullOrEmpty(reason))
            {
                warnings.Add($".piiscout-ignore line {n + 1}: entry for {glob} has no reason=\"...\" and is not applied");
                continue;
            }
            if (expires is { } e && e < now)
            {
                warnings.Add($".piiscout-ignore line {n + 1}: entry for {glob} expired on {e:yyyy-MM-dd}, its findings count again");
                continue;
            }
            entries.Add(new Entry(glob, detector, reason, expires, n + 1));
        }
        return new IgnoreList(entries, warnings);
    }

    /// <summary>The entry that covers a finding at this path (relative, forward slashes), or null.</summary>
    public Entry? Match(string relativePath, string detectorId) =>
        Entries.FirstOrDefault(e => (e.Detector == "*" || e.Detector.Equals(detectorId, StringComparison.OrdinalIgnoreCase))
                                    && e.Pattern.IsMatch(relativePath));

    /// <summary>** matches across folders, * within one folder, ? one character. A glob without "/" matches the file name anywhere.</summary>
    internal static Regex GlobToRegex(string glob)
    {
        var anywhere = !glob.Contains('/');
        var sb = new System.Text.StringBuilder(anywhere ? "(^|/)" : "^");
        for (var i = 0; i < glob.Length; i++)
        {
            var c = glob[i];
            if (c == '*' && i + 1 < glob.Length && glob[i + 1] == '*')
            {
                var slash = i + 2 < glob.Length && glob[i + 2] == '/';
                sb.Append(slash ? "(.*/)?" : ".*");
                i += slash ? 2 : 1;
            }
            else if (c == '*') sb.Append("[^/]*");
            else if (c == '?') sb.Append("[^/]");
            else sb.Append(Regex.Escape(c.ToString()));
        }
        sb.Append('$');
        return new Regex(sb.ToString(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }
}
