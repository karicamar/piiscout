using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace PiiScout.Core.Detectors;

public sealed partial class EmailDetector : Detector
{
    // Mailboxes of a role, not of a person (support@, datenschutz@). Still reported, as information only.
    private static readonly HashSet<string> RoleMailboxes = new(StringComparer.OrdinalIgnoreCase)
    {
        "info", "kontakt", "contact", "support", "service", "kundenservice", "noreply", "no-reply", "donotreply", "do-not-reply",
        "admin", "postmaster", "webmaster", "hostmaster", "abuse", "security", "privacy", "datenschutz", "dsb", "bewerbung",
        "jobs", "karriere", "careers", "sales", "vertrieb", "office", "hello", "hallo", "team", "git", "mail", "newsletter",
        "billing", "rechnung", "buchhaltung", "presse", "press", "hr", "it", "helpdesk", "notifications", "alerts",
    };

    // "logo@2x.png" is a file name, not an address.
    private static readonly HashSet<string> FileExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "css", "js", "map", "json", "xml", "txt", "pdf",
    };

    public override string Id => "PII-EMAIL";
    public override string Name => "Email address";
    public override Category Category => Category.Contact;
    public override Severity Severity => Severity.Medium;
    public override string Description =>
        "Email addresses. Addresses of a role (support@, datenschutz@) and reserved test domains (example.com, .test, .invalid) are reported as information only.";

    [GeneratedRegex(@"(?<![\w.%+\-])[A-Za-z0-9][A-Za-z0-9._%+\-]{0,63}@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24})(?![\w\-])")]
    private static partial Regex Pattern();

    public override IEnumerable<Detection> Find(LineContext line)
    {
        foreach (Match m in Pattern().Matches(line.Text))
        {
            var tld = m.Groups[1].Value;
            if (FileExtensions.Contains(tld)) continue;
            // Real TLDs are written in one case; "item-@i.Id" is Razor markup, not an address
            if (tld.Any(char.IsUpper) && tld.Any(char.IsLower)) continue;
            var at = m.Value.IndexOf('@');
            var local = m.Value[..at];
            if (local[^1] is '.' or '-') continue;
            var domain = m.Value[(at + 1)..].ToLowerInvariant();

            if (IsReservedDomain(domain))
                yield return Hit(m.Index, m.Length, m.Value, Confidence.High, testData: true, note: "reserved test domain");
            else if (RoleMailboxes.Contains(local.Split('+')[0]))
                yield return Hit(m.Index, m.Length, m.Value, Confidence.High, testData: true, note: "role mailbox, not a person");
            else
                yield return Hit(m.Index, m.Length, m.Value, Confidence.High);
        }
    }

    internal static bool IsReservedDomain(string domain) =>
        domain is "example.com" or "example.net" or "example.org" or "localhost"
        // Not reserved by RFC 2606, but used as "the example domain" everywhere: example.de, example.co.uk
        || domain.StartsWith("example.", StringComparison.Ordinal) || domain.Contains(".example.", StringComparison.Ordinal)
        || domain.EndsWith(".example.com", StringComparison.Ordinal)
        || domain.EndsWith(".example", StringComparison.Ordinal) || domain.EndsWith(".test", StringComparison.Ordinal)
        || domain.EndsWith(".invalid", StringComparison.Ordinal) || domain.EndsWith(".localhost", StringComparison.Ordinal);

    public override string Mask(string value)
    {
        var at = value.IndexOf('@');
        return value[..1] + "***" + value[at..];
    }

    public override string Normalize(string value) => value.ToLowerInvariant();
}

public sealed partial class PhoneDetector : Detector
{
    private static readonly string[] Keywords = ["tel", "phone", "telefon", "mobil", "handy", "fax", "rufnummer", "festnetz", "call", "whatsapp"];

    public override string Id => "PII-PHONE";
    public override string Name => "German phone number";
    public override Category Category => Category.Contact;
    public override Severity Severity => Severity.Medium;
    public override string Description =>
        "German phone numbers in national (area code with leading 0) and international (+49, 0049) form. National numbers without a mobile prefix need a context word (Tel., phone, Mobil) to count as likely.";

    // No dots: "01.02.2024" is a date, not a number.
    [GeneratedRegex(@"(?<![\w+\-/.])(?:\+49|0049|\(0|0)[\d \-/()]{5,19}\d(?!\w|\.\d)")]
    private static partial Regex Pattern();

    public override IEnumerable<Detection> Find(LineContext line)
    {
        foreach (Match m in Pattern().Matches(line.Text))
        {
            var value = m.Value.TrimEnd(' ', '-', '/');
            if (National(value) is not { } nsn) continue;

            var international = value.StartsWith('+') || value.StartsWith("0049", StringComparison.Ordinal);
            var mobile = nsn.Length >= 10 && nsn[0] == '1' && nsn[1] is '5' or '6' or '7';
            var confidence = line.HasContext(m.Index, Keywords) ? Confidence.High
                : international || mobile ? Confidence.Medium
                : Confidence.Low;
            yield return Hit(m.Index, value.Length, value, confidence);
        }
    }

    /// <summary>The national significant number (without 0 / +49), or null if this cannot be a German number.</summary>
    internal static string? National(string value)
    {
        var compact = Compact(value);
        string rest;
        if (compact.StartsWith("+49", StringComparison.Ordinal)) rest = compact[3..];
        else if (compact.StartsWith("0049", StringComparison.Ordinal)) rest = compact[4..];
        else if (compact.StartsWith('0')) rest = compact[1..];
        else return null;

        if (rest.StartsWith('0')) rest = rest[1..]; // +49 (0)69 ...
        // Area code plus subscriber number: at least 7 digits in practice, at most 11 (E.164 for Germany)
        if (rest.Length is < 7 or > 11 || rest[0] == '0') return null;
        foreach (var c in rest)
            if (!char.IsAsciiDigit(c)) return null;
        // Too many separators for a phone number: "0 1 2 3 4 5" is a table, not a number
        var separators = value.Count(c => c is ' ' or '-' or '/');
        return separators > 4 ? null : rest;
    }

    public override string Mask(string value)
    {
        var nsn = National(value) ?? DigitsOnly(value);
        return "+49 " + KeepEnds(nsn, 2, 2);
    }

    public override string Normalize(string value) => "+49" + (National(value) ?? DigitsOnly(value));
}

public sealed partial class DateOfBirthDetector : Detector
{
    private static readonly string[] Keywords =
        ["geburtsdatum", "geboren", "geb.", "geb ", "geburtstag", "birth", "dob", "birthday", "birthdate", "dateofbirth", "date of birth"];

    public override string Id => "PII-DOB";
    public override string Name => "Date of birth";
    public override Category Category => Category.Identity;
    public override Severity Severity => Severity.Medium;
    public override string Description =>
        "Dates (31.12.1980, 1980-12-31, 31/12/1980) that a context word or field name marks as a birth date (geb., Geburtsdatum, dob, birth_date). Dates without such context are ignored.";

    [GeneratedRegex(@"(?<![\d.\-/])(?:(?<d>\d{1,2})\.(?<m>\d{1,2})\.(?<y>\d{4})|(?<y>\d{4})-(?<m>\d{2})-(?<d>\d{2})|(?<d>\d{2})/(?<m>\d{2})/(?<y>\d{4}))(?![\d.\-/]\d)")]
    private static partial Regex Pattern();

    internal Func<DateOnly> Today { get; init; } = () => DateOnly.FromDateTime(DateTime.UtcNow);

    public override IEnumerable<Detection> Find(LineContext line)
    {
        foreach (Match m in Pattern().Matches(line.Text))
        {
            if (!line.HasContext(m.Index, Keywords)) continue;
            var y = int.Parse(m.Groups["y"].Value, CultureInfo.InvariantCulture);
            var mo = int.Parse(m.Groups["m"].Value, CultureInfo.InvariantCulture);
            var d = int.Parse(m.Groups["d"].Value, CultureInfo.InvariantCulture);
            if (y < 1900 || mo is < 1 or > 12 || d < 1 || d > DateTime.DaysInMonth(y, mo)) continue;
            if (new DateOnly(y, mo, d) > Today()) continue;
            yield return Hit(m.Index, m.Length, m.Value, Confidence.High);
        }
    }

    public override string Mask(string value)
    {
        // Keep the year (useful for age-related questions), hide day and month
        var year = Regex.Match(value, @"\d{4}").Value;
        return "**.**." + year;
    }

    public override string Normalize(string value) => DigitsOnly(value);
}

public sealed partial class IbanDetector : Detector
{
    // Published example IBANs (bank documentation, ECB/EPC examples, tutorials)
    private static readonly HashSet<string> Examples = new(StringComparer.Ordinal)
    {
        "DE89370400440532013000", "DE02120300000000202051", "DE75512108001245126199", "DE12500105170648489890",
        "GB82WEST12345698765432", "GB29NWBK60161331926819", "FR1420041010050500013M02606", "AT611904300234573201",
        "CH9300762011623852957", "NL91ABNA0417164300", "BE68539007547034", "ES9121000418450200051332",
    };

    public override string Id => "PII-IBAN";
    public override string Name => "IBAN";
    public override Category Category => Category.Financial;
    public override Severity Severity => Severity.High;
    public override string Description =>
        "International bank account numbers, compact or in groups of four. Validated by country length (ISO 13616) and the mod-97 check digits, so random strings do not match.";

    [GeneratedRegex(@"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?=[ ]?[A-Z0-9])")]
    private static partial Regex Start();

    public override IEnumerable<Detection> Find(LineContext line)
    {
        var text = line.Text;
        foreach (Match m in Start().Matches(text))
        {
            if (!Checksums.IbanLengths.TryGetValue(m.Value[..2], out var length)) continue;

            // Walk forward, allowing single spaces between groups, until the country's length is reached
            var compact = new System.Text.StringBuilder(m.Value);
            var i = m.Index + 4;
            while (compact.Length < length && i < text.Length)
            {
                var c = text[i];
                if (c == ' ' && i + 1 < text.Length && text[i + 1] != ' ') { i++; continue; }
                if (!char.IsAsciiDigit(c) && !char.IsAsciiLetterUpper(c)) break;
                compact.Append(c);
                i++;
            }
            if (compact.Length != length) continue;
            if (i < text.Length && char.IsAsciiLetterOrDigit(text[i])) continue;

            var iban = compact.ToString();
            if (!Checksums.Iban(iban)) continue;
            yield return Hit(m.Index, i - m.Index, text[m.Index..i], Confidence.High,
                testData: Examples.Contains(iban), note: Examples.Contains(iban) ? "published example IBAN" : null);
        }
    }

    public override string Mask(string value)
    {
        var c = Compact(value);
        return c[..4] + "****" + c[^4..];
    }

    public override string Normalize(string value) => Compact(value);
}

public sealed partial class PaymentCardDetector : Detector
{
    private static readonly string[] Keywords = ["card", "karte", "kreditkarte", "pan", "cc", "visa", "mastercard", "amex", "kartennummer", "cardnumber"];

    // Test numbers published by card networks and payment providers
    private static readonly HashSet<string> TestNumbers = new(StringComparer.Ordinal)
    {
        "4111111111111111", "4242424242424242", "4012888888881881", "4000056655665556", "4222222222222",
        "5555555555554444", "5105105105105100", "2223003122003222", "5200828282828210",
        "378282246310005", "371449635398431", "6011111111111117", "6011000990139424", "3530111333300000", "30569309025904",
    };

    public override string Id => "PII-CARD";
    public override string Name => "Payment card number";
    public override Category Category => Category.Financial;
    public override Severity Severity => Severity.High;
    public override string Legal => "Art. 4(1) GDPR, PCI DSS 3.3/3.5";
    public override string Description =>
        "Card numbers (PAN) of Visa, Mastercard, American Express, Discover, JCB, Diners and Maestro: Luhn check plus issuer prefix and length. Published test cards are information only.";

    [GeneratedRegex(@"(?<![\w\-.])\d(?:[ \-]?\d){11,18}(?![\w\-]|\.\d)")]
    private static partial Regex Pattern();

    public override IEnumerable<Detection> Find(LineContext line)
    {
        foreach (Match m in Pattern().Matches(line.Text))
        {
            var digits = DigitsOnly(m.Value);
            if (Brand(digits) is null || !Checksums.Luhn(digits)) continue;
            if (digits.Distinct().Count() < 2) continue; // 0000 0000 0000 0000 and similar fillers

            var grouped = m.Value.Contains(' ') || m.Value.Contains('-');
            var confidence = grouped || line.HasContext(m.Index, Keywords) ? Confidence.High : Confidence.Medium;
            var test = TestNumbers.Contains(digits);
            yield return Hit(m.Index, m.Length, m.Value, confidence, test, test ? "published test card" : null);
        }
    }

    /// <summary>Card network by issuer identification number and length, or null if none fits.</summary>
    internal static string? Brand(string d)
    {
        int Prefix(int n) => int.Parse(d.AsSpan(0, n), CultureInfo.InvariantCulture);
        var len = d.Length;
        if (len < 12) return null;
        if (d[0] == '4' && len is 13 or 16 or 19) return "Visa";
        if (len == 16 && (Prefix(2) is >= 51 and <= 55 || Prefix(4) is >= 2221 and <= 2720)) return "Mastercard";
        if (len == 15 && Prefix(2) is 34 or 37) return "Amex";
        if (len is >= 16 and <= 19 && (d.StartsWith("6011", StringComparison.Ordinal) || d.StartsWith("65", StringComparison.Ordinal) || Prefix(3) is >= 644 and <= 649)) return "Discover";
        if (len is >= 16 and <= 19 && Prefix(4) is >= 3528 and <= 3589) return "JCB";
        if (len is >= 14 and <= 19 && (Prefix(2) is 36 or 38 or 39 || Prefix(3) is >= 300 and <= 305)) return "Diners";
        if (len is >= 12 and <= 19 && (Prefix(2) is 50 or (>= 56 and <= 58) || d[0] == '6')) return "Maestro";
        return null;
    }

    public override string Mask(string value)
    {
        var d = DigitsOnly(value);
        return $"{Brand(d) ?? "card"} ****{d[^4..]}";
    }

    public override string Normalize(string value) => DigitsOnly(value);
}

public sealed partial class SteuerIdDetector : Detector
{
    private static readonly string[] Keywords =
        ["steuer", "idnr", "id-nr", "identifikationsnummer", "tin", "taxid", "tax id", "tax_id", "tax-id", "steuernummer"];

    public override string Id => "PII-DE-TAXID";
    public override string Name => "German tax ID (Steuer-ID)";
    public override Category Category => Category.GovernmentId;
    public override Severity Severity => Severity.High;
    public override string Legal => "Art. 87 GDPR, § 139b AO";
    public override string Description =>
        "The 11-digit Steuerliche Identifikationsnummer: digit distribution rule and ISO 7064 MOD 11,10 check digit. Without a context word (Steuer-ID, IdNr, TIN) it is only a low-confidence hit, because some 11-digit numbers pass by chance.";

    [GeneratedRegex(@"(?<![\w.,\-])\d{2} ?\d{3} ?\d{3} ?\d{3}(?![\w,\-]|\.\d)")]
    private static partial Regex Pattern();

    public override IEnumerable<Detection> Find(LineContext line)
    {
        foreach (Match m in Pattern().Matches(line.Text))
        {
            var digits = DigitsOnly(m.Value);
            if (!Checksums.SteuerId(digits)) continue;
            yield return Hit(m.Index, m.Length, m.Value, line.HasContext(m.Index, Keywords) ? Confidence.High : Confidence.Low);
        }
    }

    public override string Mask(string value) => KeepEnds(DigitsOnly(value), 0, 2);
    public override string Normalize(string value) => DigitsOnly(value);
}

public sealed partial class IdCardDetector : Detector
{
    private static readonly string[] Keywords =
        ["ausweis", "personalausweis", "idcard", "id card", "id-card", "passport", "reisepass", "passnummer", "pass-nr", "dokumentnummer", "document number", "documentnumber"];

    public override string Id => "PII-DE-IDCARD";
    public override string Name => "German ID card or passport number";
    public override Category Category => Category.GovernmentId;
    public override Severity Severity => Severity.High;
    public override string Legal => "Art. 87 GDPR, § 20 PAuswG";
    public override string Description =>
        "Document numbers of the German Personalausweis (since 2010) and Reisepass: nine characters from the reduced alphabet plus the ICAO 7-3-1 check digit. Without a context word it is only a low-confidence hit.";

    // The specimen documents of the Bundesdruckerei ("Erika Mustermann")
    private static readonly HashSet<string> Specimens = new(StringComparer.Ordinal) { "T220001293", "L01X00T471", "C01X00T478" };

    [GeneratedRegex(@"(?<![A-Za-z0-9])[CFGHJKLMNPRTVWXYZ][CFGHJKLMNPRTVWXYZ0-9]{8}\d(?![A-Za-z0-9])")]
    private static partial Regex Pattern();

    public override IEnumerable<Detection> Find(LineContext line)
    {
        foreach (Match m in Pattern().Matches(line.Text))
        {
            if (!Checksums.IdCardNumber(m.Value)) continue;
            if (m.Value.Count(char.IsAsciiDigit) < 3) continue; // "HTTPCLIENT" style words with one digit are names, not documents
            var specimen = Specimens.Contains(m.Value);
            yield return Hit(m.Index, m.Length, m.Value, line.HasContext(m.Index, Keywords) ? Confidence.High : Confidence.Low,
                specimen, specimen ? "specimen document (Mustermann)" : null);
        }
    }

    public override string Mask(string value) => KeepEnds(value, 0, 2);
}

public sealed partial class SocialInsuranceDetector : Detector
{
    private static readonly string[] Keywords =
        ["sozialversicherung", "svnr", "sv-nr", "sv-nummer", "svnummer", "rvnr", "rentenversicherung", "versicherungsnummer", "social security"];

    public override string Id => "PII-DE-SVNR";
    public override string Name => "German social insurance number";
    public override Category Category => Category.GovernmentId;
    public override Severity Severity => Severity.High;
    public override string Legal => "Art. 87 GDPR, § 18f SGB IV";
    public override string Description =>
        "The Rentenversicherungsnummer (12 characters: area, birth date, initial of the birth name, serial, check digit). It also reveals the birth date and gender, so it counts as highly sensitive. Validated by date and check digit.";

    [GeneratedRegex(@"(?<![A-Za-z0-9])\d{2} ?\d{6} ?[A-Z] ?\d{2} ?\d(?![A-Za-z0-9])")]
    private static partial Regex Pattern();

    public override IEnumerable<Detection> Find(LineContext line)
    {
        foreach (Match m in Pattern().Matches(line.Text))
        {
            var compact = Compact(m.Value);
            if (!Checksums.SozialversicherungsNummer(compact)) continue;
            yield return Hit(m.Index, m.Length, m.Value, line.HasContext(m.Index, Keywords) ? Confidence.High : Confidence.Medium);
        }
    }

    public override string Mask(string value) => KeepEnds(Compact(value), 2, 1);
    public override string Normalize(string value) => Compact(value);
}

public sealed partial class IpAddressDetector : Detector
{
    private static readonly string[] Keywords = ["ip", "client", "remote", "src", "source", "from", "forwarded", "login", "user"];
    private static readonly string[] NotAnAddress = ["version", "ver.", "build", "release", "oid", "snmp"];

    public override string Id => "PII-IP";
    public override string Name => "Public IP address";
    public override Category Category => Category.Network;
    public override Severity Severity => Severity.Low;
    public override string Legal => "Art. 4(1) GDPR, CJEU C-582/14 (Breyer)";
    public override string Description =>
        "Public IPv4 and IPv6 addresses, which are personal data when a person can be identified behind them (CJEU, Breyer). Private, loopback, link-local and carrier-grade NAT ranges are skipped; documentation ranges (192.0.2.0/24, 2001:db8::/32) count as test data.";

    // "/24" after the address makes it a network prefix, not one person's address
    [GeneratedRegex(@"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d|/\d)")]
    private static partial Regex V4();

    // Loose candidate (2 to 7 colons, :: allowed), IPAddress.TryParse decides
    [GeneratedRegex(@"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:]|/\d)")]
    private static partial Regex V6();

    public override IEnumerable<Detection> Find(LineContext line)
    {
        foreach (Match m in V4().Matches(line.Text))
        {
            var octets = m.Value.Split('.');
            if (octets.Any(o => o.Length > 1 && o[0] == '0')) continue; // leading zeros: version or OID
            if (octets.All(o => o.Length == 1)) continue;                // 1.2.3.4, 4.0.0.0: a four-part version number
            if (!IPAddress.TryParse(m.Value, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork) continue;
            if (line.HasContext(m.Index, NotAnAddress)) continue;
            if (Classify(ip) is var kind and not AddressKind.Internal)
                yield return Hit(m.Index, m.Length, m.Value, Confidence(line, m.Index), kind == AddressKind.Documentation,
                    kind == AddressKind.Documentation ? "documentation range" : null);
        }

        foreach (Match m in V6().Matches(line.Text))
        {
            if (m.Value.Count(c => c == ':') < 2) continue;
            if (!IPAddress.TryParse(m.Value, out var ip) || ip.AddressFamily != AddressFamily.InterNetworkV6) continue;
            if (Classify(ip) is var kind and not AddressKind.Internal)
                yield return Hit(m.Index, m.Length, m.Value, Confidence(line, m.Index), kind == AddressKind.Documentation,
                    kind == AddressKind.Documentation ? "documentation range" : null);
        }
    }

    private static Confidence Confidence(LineContext line, int index) =>
        line.HasContext(index, Keywords) ? Core.Confidence.High : Core.Confidence.Medium;

    internal enum AddressKind { Public, Internal, Documentation }

    internal static AddressKind Classify(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            if ((b[0] == 192 && b[1] == 0 && b[2] == 2) || (b[0] == 198 && b[1] == 51 && b[2] == 100) || (b[0] == 203 && b[1] == 0 && b[2] == 113))
                return AddressKind.Documentation;
            var internalRange = b[0] is 0 or 10 or 127 || b[0] >= 224
                || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] is >= 64 and <= 127)
                || (b[0] == 198 && b[1] is 18 or 19);
            return internalRange ? AddressKind.Internal : AddressKind.Public;
        }

        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return AddressKind.Documentation;
        return (b[0] & 0xE0) == 0x20 ? AddressKind.Public : AddressKind.Internal; // only 2000::/3 is global unicast
    }

    public override string Mask(string value)
    {
        if (value.Contains(':'))
        {
            var groups = value.Split(':');
            return $"{groups[0]}:{groups[1]}:****";
        }
        var octets = value.Split('.');
        return $"{octets[0]}.{octets[1]}.*.*";
    }

    public override string Normalize(string value) => IPAddress.TryParse(value, out var ip) ? ip.ToString() : value;
}

public sealed partial class HealthDiagnosisDetector : Detector
{
    private static readonly string[] Keywords =
        ["diagnose", "diagnosis", "icd", "befund", "erkrankung", "krankheit", "arbeitsunfähig", "arbeitsunfaehig", "au-bescheinigung", "krankschreibung", "symptom", "therapie", "condition"];

    public override string Id => "PII-HEALTH-ICD";
    public override string Name => "Diagnosis code (ICD-10)";
    public override Category Category => Category.SpecialCategory;
    public override Severity Severity => Severity.Critical;
    public override string Legal => "Art. 9(1) GDPR (health data)";
    public override string Description =>
        "ICD-10 / ICD-10-GM diagnosis codes (a letter, two digits, optional decimals and the certainty marker G/V/Z/A) next to a word like Diagnose, ICD, Befund or Krankschreibung. Health data is a special category under Art. 9 GDPR and may only be processed under strict conditions.";

    [GeneratedRegex(@"(?<![\w.])[A-TV-Z]\d{2}(?:\.\d{1,2})?(?: ?[GVZA])?(?![\w.])")]
    private static partial Regex Pattern();

    public override IEnumerable<Detection> Find(LineContext line)
    {
        foreach (Match m in Pattern().Matches(line.Text))
            if (line.HasContext(m.Index, Keywords))
                yield return Hit(m.Index, m.Length, m.Value, Confidence.Medium);
    }

    public override string Mask(string value) => value[..1] + "**.*";
}

/// <summary>
/// Special categories (Art. 9 GDPR) are rarely recognizable by their values ("rk", "ja", "F32.1") but often by the column:
/// a CSV with a "Konfession" column, JSON with "health_condition". Any non-empty value in such a field is reported.
/// </summary>
public sealed class SpecialCategoryFieldDetector : Detector
{
    internal static readonly (string Term, string Meaning)[] Terms =
    [
        ("religion", "religious belief"),
        ("konfession", "religious belief"),
        ("kirchensteuer", "religious belief (church tax reveals the denomination)"),
        ("gewerkschaft", "trade union membership"),
        ("tradeunion", "trade union membership"),
        ("ethnic", "racial or ethnic origin"),
        ("ethnie", "racial or ethnic origin"),
        ("sexualorient", "sexual orientation"),
        ("sexuelleorient", "sexual orientation"),
        ("diagnos", "health data"),
        ("krankheit", "health data"),
        ("gesundheit", "health data"),
        ("health", "health data"),
        ("behinderung", "health data (disability)"),
        ("schwerbehindert", "health data (disability)"),
        ("disability", "health data (disability)"),
        ("genetic", "genetic data"),
        ("biometri", "biometric data"),
        ("politicalopinion", "political opinion"),
        ("politischemeinung", "political opinion"),
    ];

    // Technical names that contain a term: "healthcheck": "ok" and "diagnostics": true are not about a person
    private static readonly string[] NotPersonal = ["healthcheck", "healthz", "healthy", "healthstatus", "healthprobe", "healthendpoint", "diagnostic"];

    private static readonly HashSet<string> Empty = new(StringComparer.OrdinalIgnoreCase) { "", "null", "none", "n/a", "na", "-", "\"\"" };

    // Output of the redact command: "[11 chars]" or "[ART9-FIELD:3f2a91c04b5e6d7f]" is no longer the value
    internal static readonly Regex Redacted = new(@"^\[(?:\d+ chars|[A-Z0-9\-]+:[0-9a-f]{16})\]$", RegexOptions.Compiled);

    public override string Id => "PII-ART9-FIELD";
    public override string Name => "Special category field";
    public override Category Category => Category.SpecialCategory;
    public override Severity Severity => Severity.Critical;
    public override string Legal => "Art. 9(1) GDPR";
    public override string Description =>
        "A filled CSV column, JSON property or key=value field whose name points to a special category of personal data: religion (incl. Kirchensteuermerkmal), trade union, ethnic origin, health, disability, sexual orientation, genetic or biometric data.";

    public override IEnumerable<Detection> Find(LineContext line)
    {
        foreach (var field in line.Fields)
        {
            if (Meaning(field.Name) is not { } meaning) continue;
            var value = line.Text.Substring(field.Start, field.Length).Trim().Trim('"');
            if (Empty.Contains(value) || Redacted.IsMatch(value)) continue;
            yield return Hit(field.Start, field.Length, line.Text.Substring(field.Start, field.Length), Confidence.Medium, note: meaning);
        }
    }

    internal static string? Meaning(string fieldName)
    {
        var name = LineContext.Normalize(fieldName);
        foreach (var technical in NotPersonal)
            if (name.Contains(technical, StringComparison.Ordinal))
                return null;
        foreach (var (term, meaning) in Terms)
            if (name.Contains(term, StringComparison.Ordinal))
                return meaning;
        return null;
    }

    public override string Mask(string value) => $"[{value.Trim().Trim('"').Length} chars]";
}

/// <summary>
/// Names have no check digit, but they are rarely alone: a column "Nachname", a JSON property "debtorName",
/// debtor="..." in a log. Only such fields are reported, and only values that look like a name.
/// </summary>
public sealed partial class PersonNameFieldDetector : Detector
{
    private static readonly string[] Terms =
    [
        "vorname", "nachname", "firstname", "lastname", "fullname", "surname", "givenname", "familyname", "geburtsname",
        "kontoinhaber", "accountholder", "accountowner", "debtor", "creditor", "schuldner", "glaeubiger", "gläubiger",
        "empfaenger", "empfänger", "recipientname", "customername", "kundenname", "patientname", "patient", "mitarbeitername",
        "employeename", "contactname", "ansprechpartner", "personname",
    ];

    // Exactly "name" is only a person in tables (a CSV column); in JSON it is usually a product, package or service name
    private static readonly string[] TabularOnly = ["name", "kunde", "customer", "inhaber", "mitarbeiter"];

    // Technical fields that only contain a name term, such as debtorAgent or creditorId
    private static readonly string[] NotAName = ["id", "iban", "bic", "agent", "account", "konto", "nummer", "number", "nr", "type", "ref", "count", "field"];

    public override string Id => "PII-NAME-FIELD";
    public override string Name => "Person name (by field)";
    public override Category Category => Category.Identity;
    public override Severity Severity => Severity.Medium;
    public override string Description =>
        "Values of fields whose name marks a person's name: Vorname, Nachname, Kontoinhaber, debtor, customerName, and the plain column \"Name\" in CSV files. The value must look like a name (letters, no digits or @).";

    [GeneratedRegex(@"^[\p{L}][\p{L}'’.\-]*(?: [\p{L}][\p{L}'’.\-]*){0,4}$")]
    private static partial Regex LooksLikeName();

    public override IEnumerable<Detection> Find(LineContext line)
    {
        foreach (var field in line.Fields)
        {
            if (!IsNameField(field.Name, line.Tabular)) continue;
            var raw = line.Text.Substring(field.Start, field.Length);
            var value = raw.Trim().Trim('"').Trim();
            if (value.Length is < 2 or > 80 || !LooksLikeName().IsMatch(value)) continue;
            // Initials only ("E. M.", the masked form) do not identify anyone on their own
            if (!value.Split(' ').Any(p => p.Count(char.IsLetter) >= 2)) continue;
            var start = field.Start + raw.IndexOf(value, StringComparison.Ordinal);
            yield return Hit(start, value.Length, value, Confidence.Medium);
        }
    }

    internal static bool IsNameField(string fieldName, bool tabular)
    {
        var name = LineContext.Normalize(fieldName);
        if (tabular && TabularOnly.Contains(name)) return true;
        foreach (var term in Terms)
        {
            if (!name.Contains(term, StringComparison.Ordinal)) continue;
            var rest = name.Replace(term, "", StringComparison.Ordinal);
            if (rest.Length == 0 || rest == "name" || !NotAName.Any(n => rest.Contains(n, StringComparison.Ordinal))) return true;
        }
        return false;
    }

    public override string Mask(string value) =>
        string.Join(' ', value.Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(p => p[..1] + "."));

    public override string Normalize(string value) => value.ToLowerInvariant();
}
