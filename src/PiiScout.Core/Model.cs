namespace PiiScout.Core;

/// <summary>What kind of personal data a detector finds. Drives severity and the data map.</summary>
public enum Category
{
    Contact,
    Identity,
    Financial,
    GovernmentId,
    Network,
    SpecialCategory,
}

public enum Severity
{
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// <summary>How sure a detector is. Check digits and context words raise it.</summary>
public enum Confidence
{
    Low,
    Medium,
    High,
}

/// <summary>A raw hit inside one line, before masking. The value never leaves the scanner.</summary>
public sealed record Detection(
    string DetectorId,
    int Index,
    int Length,
    string Value,
    Confidence Confidence,
    bool TestData = false,
    string? Note = null);

/// <summary>A reported finding. Contains only the masked value and a keyed fingerprint, never the value itself.</summary>
public sealed record Finding(
    string DetectorId,
    string Name,
    Category Category,
    Severity Severity,
    Confidence Confidence,
    string Path,
    int Line,
    int Column,
    string Masked,
    string Fingerprint,
    string? Field,
    bool TestData,
    string? Note)
{
    public bool Suppressed { get; init; }
    public string? SuppressedBecause { get; init; }
}

public static class CategoryInfo
{
    public static string Label(Category c) => c switch
    {
        Category.Contact => "Contact data",
        Category.Identity => "Identity data",
        Category.Financial => "Financial data",
        Category.GovernmentId => "Government identifier",
        Category.Network => "Online identifier",
        Category.SpecialCategory => "Special category (Art. 9 GDPR)",
        _ => c.ToString(),
    };

    public static string German(Category c) => c switch
    {
        Category.Contact => "Kontaktdaten",
        Category.Identity => "Identitätsdaten",
        Category.Financial => "Bank- und Zahlungsdaten",
        Category.GovernmentId => "Amtliche Kennnummer",
        Category.Network => "Online-Kennung",
        Category.SpecialCategory => "Besondere Kategorie (Art. 9 DSGVO)",
        _ => c.ToString(),
    };
}
