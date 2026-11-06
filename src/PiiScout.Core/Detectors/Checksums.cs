namespace PiiScout.Core.Detectors;

/// <summary>
/// Check digit algorithms. A pattern alone matches lots of order numbers and timestamps;
/// the check digit is what turns "11 digits" into "a valid tax id".
/// </summary>
public static class Checksums
{
    /// <summary>Luhn (mod 10), used by payment card numbers.</summary>
    public static bool Luhn(ReadOnlySpan<char> digits)
    {
        if (digits.Length < 2) return false;
        var sum = 0;
        var doubleIt = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            if (!char.IsAsciiDigit(digits[i])) return false;
            var d = digits[i] - '0';
            if (doubleIt)
            {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
            doubleIt = !doubleIt;
        }
        return sum % 10 == 0;
    }

    // ISO 13616 IBAN lengths per country (SEPA countries plus common others).
    internal static readonly Dictionary<string, int> IbanLengths = new()
    {
        ["AD"] = 24, ["AE"] = 23, ["AL"] = 28, ["AT"] = 20, ["BA"] = 20, ["BE"] = 16, ["BG"] = 22, ["BH"] = 22,
        ["CH"] = 21, ["CY"] = 28, ["CZ"] = 24, ["DE"] = 22, ["DK"] = 18, ["EE"] = 20, ["ES"] = 24, ["FI"] = 18,
        ["FO"] = 18, ["FR"] = 27, ["GB"] = 22, ["GI"] = 23, ["GL"] = 18, ["GR"] = 27, ["HR"] = 21, ["HU"] = 28,
        ["IE"] = 22, ["IL"] = 23, ["IS"] = 26, ["IT"] = 27, ["LI"] = 21, ["LT"] = 20, ["LU"] = 20, ["LV"] = 21,
        ["MC"] = 27, ["ME"] = 22, ["MK"] = 19, ["MT"] = 31, ["NL"] = 18, ["NO"] = 15, ["PL"] = 28, ["PT"] = 25,
        ["RO"] = 24, ["RS"] = 22, ["SA"] = 24, ["SE"] = 24, ["SI"] = 19, ["SK"] = 24, ["SM"] = 27, ["TR"] = 26,
        ["UA"] = 29, ["VA"] = 22, ["XK"] = 20,
    };

    /// <summary>IBAN: known country, exact length for that country, and mod 97 == 1 (ISO 7064 MOD 97-10).</summary>
    public static bool Iban(string compact)
    {
        if (compact.Length < 15 || compact.Length > 34) return false;
        var country = compact[..2];
        if (!IbanLengths.TryGetValue(country, out var length) || length != compact.Length) return false;
        if (!char.IsAsciiDigit(compact[2]) || !char.IsAsciiDigit(compact[3])) return false;

        // Move the first four characters to the end, letters become 10..35, then mod 97 piece by piece.
        var remainder = 0;
        foreach (var c in compact[4..] + compact[..4])
        {
            if (char.IsAsciiDigit(c))
                remainder = (remainder * 10 + (c - '0')) % 97;
            else if (char.IsAsciiLetterUpper(c))
                remainder = (remainder * 100 + (c - 'A' + 10)) % 97;
            else
                return false;
        }
        return remainder == 1;
    }

    /// <summary>
    /// German tax identification number (Steuerliche Identifikationsnummer, § 139b AO): 11 digits, no leading zero,
    /// in the first ten digits exactly one digit occurs twice or three times (three times never directly in a row),
    /// check digit by ISO 7064 MOD 11,10.
    /// </summary>
    public static bool SteuerId(ReadOnlySpan<char> s)
    {
        if (s.Length != 11 || s[0] == '0') return false;
        foreach (var c in s)
            if (!char.IsAsciiDigit(c)) return false;

        Span<int> counts = stackalloc int[10];
        for (var i = 0; i < 10; i++) counts[s[i] - '0']++;
        int repeated = 0, missing = 0;
        foreach (var n in counts)
        {
            if (n == 0) missing++;
            else if (n is 2 or 3) repeated++;
            else if (n > 3) return false;
        }
        // One digit repeated: twice means one digit is missing, three times means two are missing.
        if (repeated != 1 || missing is not (1 or 2)) return false;
        for (var i = 0; i + 2 < 10; i++)
            if (s[i] == s[i + 1] && s[i + 1] == s[i + 2]) return false;

        return Iso7064Mod11_10(s[..10]) == s[10] - '0';
    }

    internal static int Iso7064Mod11_10(ReadOnlySpan<char> digits)
    {
        var product = 10;
        foreach (var c in digits)
        {
            var sum = (c - '0' + product) % 10;
            if (sum == 0) sum = 10;
            product = sum * 2 % 11;
        }
        var check = 11 - product;
        return check == 10 ? 0 : check;
    }

    private const string IdCardAlphabet = "CFGHJKLMNPRTVWXYZ";

    /// <summary>
    /// German identity card number (Personalausweis since 2010, also passports): nine characters
    /// from a reduced alphabet (no vowels, no B, D, Q, S), starting with a letter, then a check digit with weights 7-3-1 (ICAO 9303).
    /// </summary>
    public static bool IdCardNumber(ReadOnlySpan<char> s)
    {
        if (s.Length != 10 || !char.IsAsciiDigit(s[9])) return false;
        if (!IdCardAlphabet.Contains(s[0])) return false;
        for (var i = 1; i < 9; i++)
            if (!char.IsAsciiDigit(s[i]) && !IdCardAlphabet.Contains(s[i])) return false;
        return Icao7_3_1(s[..9]) == s[9] - '0';
    }

    internal static int Icao7_3_1(ReadOnlySpan<char> s)
    {
        ReadOnlySpan<int> weights = [7, 3, 1];
        var sum = 0;
        for (var i = 0; i < s.Length; i++)
        {
            var v = char.IsAsciiDigit(s[i]) ? s[i] - '0' : s[i] - 'A' + 10;
            sum += v * weights[i % 3];
        }
        return sum % 10;
    }

    /// <summary>
    /// German social insurance number (Rentenversicherungsnummer): area (2 digits), birth date DDMMYY,
    /// initial of the birth name, serial (2 digits), check digit. The letter becomes its two-digit position in the
    /// alphabet, the 12 digits are weighted 2-1-2-5-7-1-2-1-2-1-2-1, the digit sums of the products are added, mod 10.
    /// </summary>
    public static bool SozialversicherungsNummer(ReadOnlySpan<char> s)
    {
        if (s.Length != 12 || !char.IsAsciiLetterUpper(s[8])) return false;
        for (var i = 0; i < 12; i++)
            if (i != 8 && !char.IsAsciiDigit(s[i])) return false;

        var day = (s[2] - '0') * 10 + (s[3] - '0');
        var month = (s[4] - '0') * 10 + (s[5] - '0');
        if (day > 50) day -= 50; // when the serials for one birth date run out, the day is continued as day + 50
        if (day is < 1 or > 31 || month is < 1 or > 12) return false;

        var letter = s[8] - 'A' + 1;
        Span<int> digits = [s[0] - '0', s[1] - '0', s[2] - '0', s[3] - '0', s[4] - '0', s[5] - '0', s[6] - '0', s[7] - '0',
            letter / 10, letter % 10, s[9] - '0', s[10] - '0'];
        ReadOnlySpan<int> weights = [2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1];
        var sum = 0;
        for (var i = 0; i < 12; i++)
        {
            var p = digits[i] * weights[i];
            sum += p / 10 + p % 10;
        }
        return sum % 10 == s[11] - '0';
    }
}
