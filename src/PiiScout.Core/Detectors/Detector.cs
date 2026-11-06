namespace PiiScout.Core.Detectors;

/// <summary>Finds one type of personal data in a line. Implementations validate (check digits, ranges) before reporting.</summary>
public abstract class Detector
{
    public abstract string Id { get; }
    public abstract string Name { get; }
    public abstract Category Category { get; }
    public abstract Severity Severity { get; }

    /// <summary>Short legal reference shown in reports, e.g. "Art. 4 Nr. 1 GDPR".</summary>
    public virtual string Legal => "Art. 4(1) GDPR";

    /// <summary>One or two sentences: what it finds and how it validates, used as SARIF rule help.</summary>
    public abstract string Description { get; }

    public abstract IEnumerable<Detection> Find(LineContext line);

    /// <summary>The value as reports show it: enough to locate it, not enough to misuse it.</summary>
    public abstract string Mask(string value);

    /// <summary>Canonical form for fingerprints, so "DE89 3704 ..." and "DE893704..." count as one value.</summary>
    public virtual string Normalize(string value) => value;

    protected Detection Hit(int index, int length, string value, Confidence confidence, bool testData = false, string? note = null) =>
        new(Id, index, length, value, confidence, testData, note);

    internal static string KeepEnds(string value, int head, int tail, char fill = '*')
    {
        if (value.Length <= head + tail) return new string(fill, value.Length);
        return value[..head] + new string(fill, value.Length - head - tail) + value[^tail..];
    }

    internal static string DigitsOnly(string value)
    {
        Span<char> buffer = stackalloc char[value.Length];
        var n = 0;
        foreach (var c in value)
            if (char.IsAsciiDigit(c)) buffer[n++] = c;
        return new string(buffer[..n]);
    }

    internal static string Compact(string value)
    {
        Span<char> buffer = stackalloc char[value.Length];
        var n = 0;
        foreach (var c in value)
            if (c is not (' ' or '-' or '/' or '(' or ')' or '\t')) buffer[n++] = c;
        return new string(buffer[..n]);
    }
}

public static class DetectorCatalog
{
    /// <summary>All detectors in a fixed order (ids are stable, they appear in SARIF and ignore files).</summary>
    public static IReadOnlyList<Detector> All { get; } =
    [
        new EmailDetector(),
        new PhoneDetector(),
        new DateOfBirthDetector(),
        new IbanDetector(),
        new PaymentCardDetector(),
        new SteuerIdDetector(),
        new IdCardDetector(),
        new SocialInsuranceDetector(),
        new IpAddressDetector(),
        new HealthDiagnosisDetector(),
        new SpecialCategoryFieldDetector(),
        new PersonNameFieldDetector(),
    ];

    public static Detector Get(string id) =>
        All.FirstOrDefault(d => d.Id.Equals(id, StringComparison.OrdinalIgnoreCase))
        ?? throw new KeyNotFoundException($"Unknown detector {id}");
}
