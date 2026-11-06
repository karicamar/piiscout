using PiiScout.Core;
using PiiScout.Core.Detectors;

namespace PiiScout.Tests;

public class EmailTests
{
    private readonly EmailDetector d = new();

    [Fact]
    public void FindsAddressAndMasksIt()
    {
        var hit = T.Single(d, "contact erika.muster84@gmx.de today");
        Assert.Equal("erika.muster84@gmx.de", hit.Value);
        Assert.False(hit.TestData);
        Assert.Equal("e***@gmx.de", d.Mask(hit.Value));
    }

    [Theory]
    [InlineData("alice@example.com")]
    [InlineData("bob@shop.test")]
    [InlineData("x@mail.example")]
    [InlineData("y@host.invalid")]
    [InlineData("lena@example.de")]
    [InlineData("tom@mail.example.co.uk")]
    public void ReservedDomainsAreTestData(string address) => Assert.True(T.Single(d, address).TestData);

    [Theory]
    [InlineData("datenschutz@firma.de")]
    [InlineData("noreply@firma.de")]
    [InlineData("support+tickets@firma.de")]
    public void RoleMailboxesAreNotPeople(string address)
    {
        var hit = T.Single(d, address);
        Assert.True(hit.TestData);
        Assert.Contains("role", hit.Note);
    }

    [Theory]
    [InlineData("logo@2x.png")]
    [InlineData("react@18.3.1")]
    [InlineData("@scope/package")]
    [InlineData("<div id=\"item-@i.Id\">")]   // Razor markup
    [InlineData("first.@last.de")]
    public void FileNamesAndPackagesAreNotAddresses(string text) => Assert.Empty(T.Hits(d, text));

    [Fact]
    public void NormalizesCase() => Assert.Equal(d.Normalize("Erika@GMX.de"), d.Normalize("erika@gmx.de"));
}

public class PhoneTests
{
    private readonly PhoneDetector d = new();

    [Theory]
    [InlineData("+49 69 4711 0815", Confidence.Medium)]
    [InlineData("0049 69 47110815", Confidence.Medium)]
    [InlineData("0171 9876543", Confidence.Medium)]   // mobile prefix
    [InlineData("069 8765 432", Confidence.Low)]      // national landline without context
    [InlineData("Tel.: 069 8765 432", Confidence.High)]
    [InlineData("+49 (0)69 87654321", Confidence.Medium)]
    public void Confidence_(string text, Confidence expected) => Assert.Equal(expected, T.Single(d, text).Confidence);

    [Theory]
    [InlineData("01.02.2024")]       // date
    [InlineData("v0.12.345678")]
    [InlineData("order 0000123")]    // national number would start with 0
    [InlineData("12:30 0 1 2 3 4 5 6")] // a table, not a number
    [InlineData("0815")]             // too short
    [InlineData("+49 69 1234")]      // too short for a real number
    public void NotPhoneNumbers(string text) => Assert.Empty(T.Hits(d, text));

    [Fact]
    public void SameNumberInDifferentFormatsNormalizesToOne()
    {
        Assert.Equal("+496947110815", d.Normalize("+49 69 4711 0815"));
        Assert.Equal("+496947110815", d.Normalize("069 4711-0815"));
        Assert.Equal("+496947110815", d.Normalize("0049 (0)69 47110815"));
    }

    [Fact]
    public void MaskKeepsOnlyEnds() => Assert.Equal("+49 69******15", d.Mask("+49 69 4711 0815"));
}

public class DateOfBirthTests
{
    private readonly DateOfBirthDetector d = new() { Today = () => new DateOnly(2026, 11, 7) };

    [Theory]
    [InlineData("geb. 14.03.1984")]
    [InlineData("Geburtsdatum: 1984-03-14")]
    [InlineData("\"date_of_birth\": \"14/03/1984\"")]
    [InlineData("dob=1984-03-14")]
    public void FindsBirthDatesWithContext(string text) => Assert.Equal(Confidence.High, T.Single(d, text).Confidence);

    [Theory]
    [InlineData("invoice date 14.03.1984")]     // no context
    [InlineData("geboren am 31.02.1984")]       // no such date
    [InlineData("geboren am 01.01.2030")]       // future
    [InlineData("geb. 01.01.1850")]             // before 1900
    public void IgnoresOtherDates(string text) => Assert.Empty(T.Hits(d, text));

    [Fact]
    public void LeapDayIsValid() => Assert.Single(T.Hits(d, "geb. 29.02.1988"));

    [Fact]
    public void MaskKeepsYear() => Assert.Equal("**.**.1984", d.Mask("1984-03-14"));
}

public class IbanTests
{
    private readonly IbanDetector d = new();

    [Theory]
    [InlineData("DE83924884111604672105")]
    [InlineData("IBAN: DE83 9248 8411 1604 6721 05")]
    [InlineData("iban=DE83924884111604672105,")]
    public void FindsCompactAndGrouped(string text)
    {
        var hit = T.Single(d, text);
        Assert.Equal("DE83924884111604672105", d.Normalize(hit.Value));
        Assert.Equal("DE83****2105", d.Mask(hit.Value));
    }

    [Fact]
    public void StopsAtCountryLengthEvenWhenTextFollows()
    {
        var hit = T.Single(d, "DE83 9248 8411 1604 6721 05 EUR 12");
        Assert.Equal("DE83 9248 8411 1604 6721 05", hit.Value);
    }

    [Theory]
    [InlineData("DE83924884111604672106")]  // wrong check digits
    [InlineData("XDE83924884111604672105")] // glued to a letter
    [InlineData("DE839248841116046721051")] // one too long
    public void RejectsInvalid(string text) => Assert.Empty(T.Hits(d, text));

    [Fact]
    public void PublishedExampleIsTestData() => Assert.True(T.Single(d, "DE89 3704 0044 0532 0130 00").TestData);
}

public class PaymentCardTests
{
    private readonly PaymentCardDetector d = new();

    [Theory]
    [InlineData("4597602046290718", "Visa", Confidence.Medium)]
    [InlineData("4597 6020 4629 0718", "Visa", Confidence.High)]  // grouped like a card
    [InlineData("card=5255907003467112", "Mastercard", Confidence.High)] // context
    public void FindsCards(string text, string brand, Confidence confidence)
    {
        var hit = T.Single(d, text);
        Assert.Equal(confidence, hit.Confidence);
        Assert.StartsWith(brand, d.Mask(hit.Value));
        Assert.EndsWith("****" + hit.Value.Replace(" ", "")[^4..], d.Mask(hit.Value));
    }

    [Theory]
    [InlineData("4111 1111 1111 1111")]
    [InlineData("5555555555554444")]
    [InlineData("378282246310005")]
    public void PublishedTestCardsAreTestData(string text) => Assert.True(T.Single(d, text).TestData);

    [Theory]
    [InlineData("4597602046290719")]   // Luhn fails
    [InlineData("1234567812345670")]   // Luhn ok, but no issuer starts with 1
    [InlineData("1700000000000")]      // Unix timestamp in ms
    [InlineData("0000 0000 0000 0000")]
    [InlineData("amount 4597602046290718.50")]
    public void RejectsNonCards(string text) => Assert.Empty(T.Hits(d, text));

    [Theory]
    [InlineData("4111111111111111", "Visa")]
    [InlineData("2223003122003222", "Mastercard")]
    [InlineData("371449635398431", "Amex")]
    [InlineData("6011111111111117", "Discover")]
    [InlineData("3530111333300000", "JCB")]
    [InlineData("30569309025904", "Diners")]
    public void Brands(string number, string brand) => Assert.Equal(brand, PaymentCardDetector.Brand(number));
}

public class GermanIdTests
{
    [Theory]
    [InlineData("Steuer-ID: 86095742719", Confidence.High)]
    [InlineData("\"steuer_id\":\"20692815242\"", Confidence.High)]
    [InlineData("IdNr 86 095 742 719", Confidence.High)]
    [InlineData("ref 86095742719", Confidence.Low)]
    public void TaxId(string text, Confidence confidence) => Assert.Equal(confidence, T.Single(new SteuerIdDetector(), text).Confidence);

    [Theory]
    [InlineData("Steuer-ID: 86095742718")]
    [InlineData("amount 1.86095742719")]
    public void TaxIdRejects(string text) => Assert.Empty(T.Hits(new SteuerIdDetector(), text));

    [Fact]
    public void TaxIdMaskKeepsLastTwo() => Assert.Equal("*********19", new SteuerIdDetector().Mask("86 095 742 719"));

    [Theory]
    [InlineData("Ausweisnummer XT3H4M37P1", Confidence.High, false)]
    [InlineData("doc XT3H4M37P1", Confidence.Low, false)]
    [InlineData("Personalausweis T220001293", Confidence.High, true)]
    public void IdCard(string text, Confidence confidence, bool specimen)
    {
        var hit = T.Single(new IdCardDetector(), text);
        Assert.Equal(confidence, hit.Confidence);
        Assert.Equal(specimen, hit.TestData);
    }

    [Theory]
    [InlineData("XT3H4M37P2")]   // check digit
    [InlineData("HTTPCLNT9X1")]  // 11 chars
    [InlineData("xt3h4m37p1")]   // lower case
    public void IdCardRejects(string text) => Assert.Empty(T.Hits(new IdCardDetector(), text));

    [Theory]
    [InlineData("SV-Nummer 65 170839 J 00 3", Confidence.High)]
    [InlineData("<SVNummer>77250771C010</SVNummer>", Confidence.High)]
    [InlineData("77250771C010", Confidence.Medium)]
    public void SocialInsurance(string text, Confidence confidence) =>
        Assert.Equal(confidence, T.Single(new SocialInsuranceDetector(), text).Confidence);

    [Fact]
    public void SocialInsuranceMask() => Assert.Equal("65*********3", new SocialInsuranceDetector().Mask("65 170839 J 00 3"));
}

public class IpAddressTests
{
    private readonly IpAddressDetector d = new();

    [Theory]
    [InlineData("ip=93.184.216.34", Confidence.High)]
    [InlineData("seen 93.184.216.34 twice", Confidence.Medium)]
    [InlineData("client=2606:2800:220:1:248:1893:25c8:1946", Confidence.High)]
    public void PublicAddresses(string text, Confidence confidence) => Assert.Equal(confidence, T.Single(d, text).Confidence);

    [Theory]
    [InlineData("10.20.0.15")]
    [InlineData("192.168.1.20")]
    [InlineData("172.20.1.1")]
    [InlineData("127.0.0.1")]
    [InlineData("100.64.3.2")]     // carrier-grade NAT
    [InlineData("169.254.10.10")]
    [InlineData("fe80::1")]
    [InlineData("::1")]
    [InlineData("fd12:3456:789a::1")] // unique local
    public void InternalAddressesAreSkipped(string text) => Assert.Empty(T.Hits(d, text));

    [Theory]
    [InlineData("version 10.0.400.12")]
    [InlineData("oid 1.3.6.1")]     // object identifier, not an address
    [InlineData("01.02.03.04")]     // leading zeros
    [InlineData("999.1.1.1")]
    [InlineData("12:30:45")]
    [InlineData("00:1A:2B:3C:4D:5E")] // MAC address
    [InlineData("allow 93.184.216.0/24")] // network prefix
    [InlineData("\"1.2.3.4\" < \"1.2.3.5\"")] // four-part versions
    [InlineData("only 2000::/3 is global")]
    public void NotAddresses(string text) => Assert.Empty(T.Hits(d, text));

    [Theory]
    [InlineData("203.0.113.7")]
    [InlineData("198.51.100.1")]
    [InlineData("2001:db8::42")]
    public void DocumentationRangesAreTestData(string text) => Assert.True(T.Single(d, text).TestData);

    [Fact]
    public void Masks()
    {
        Assert.Equal("93.184.*.*", d.Mask("93.184.216.34"));
        Assert.Equal("2606:2800:****", d.Mask("2606:2800:220:1:248:1893:25c8:1946"));
    }
}

public class SpecialCategoryTests
{
    [Theory]
    [InlineData("Diagnose F32.1 G")]
    [InlineData("\"icd\": \"J45.0\"")]
    [InlineData("Krankschreibung wegen M54.5")]
    public void DiagnosisCodesWithContext(string text) => Assert.Single(T.Hits(new HealthDiagnosisDetector(), text));

    [Theory]
    [InlineData("Seat F32 is free")]
    [InlineData("Take the A66 exit")]
    public void CodesWithoutContextAreIgnored(string text) => Assert.Empty(T.Hits(new HealthDiagnosisDetector(), text));

    [Theory]
    [InlineData("<Kirchensteuer>rk</Kirchensteuer>", "religious belief (church tax reveals the denomination)")]
    [InlineData("\"health_condition\": \"asthma\"", "health data")]
    [InlineData("gewerkschaft=verdi", "trade union membership")]
    [InlineData("<Schwerbehindert>ja</Schwerbehindert>", "health data (disability)")]
    public void Art9Fields(string text, string meaning) => Assert.Equal(meaning, T.Single(new SpecialCategoryFieldDetector(), text).Note);

    [Theory]
    [InlineData("<Kirchensteuer>-</Kirchensteuer>")]
    [InlineData("\"religion\": null")]
    [InlineData("\"healthcheck\": \"ok\"")]
    [InlineData("\"diagnostics\": \"enabled\"")]
    [InlineData("healthz=ok")]
    public void EmptyOrTechnicalFieldsAreIgnored(string text) => Assert.Empty(T.Hits(new SpecialCategoryFieldDetector(), text));

    [Fact]
    public void MaskShowsOnlyLength() => Assert.Equal("[2 chars]", new SpecialCategoryFieldDetector().Mask("\"rk\""));
}

public class NameFieldTests
{
    private readonly PersonNameFieldDetector d = new();

    [Theory]
    [InlineData("debtor=\"Jonas Beispiel\"", "Jonas Beispiel")]
    [InlineData("\"nachname\": \"Müller-Lüdenscheidt\"", "Müller-Lüdenscheidt")]
    [InlineData("<Kontoinhaber>Leyla Demir</Kontoinhaber>", "Leyla Demir")]
    [InlineData("\"customerName\": \"Ana O'Neil\"", "Ana O'Neil")]
    public void NamesInNamedFields(string text, string name) => Assert.Equal(name, T.Single(d, text).Value);

    [Theory]
    [InlineData("\"name\": \"piiscout\"")]               // package.json: not a person
    [InlineData("\"debtorAgent\": \"COBADEFFXXX\"")]     // technical field
    [InlineData("\"creditorId\": \"DE98ZZZ09999999999\"")]
    [InlineData("\"customerNameField\": \"Label\"")]
    [InlineData("\"lastname\": \"user42\"")]             // digits: not a name
    [InlineData("\"firstname\": \"\"")]
    public void NotNames(string text) => Assert.Empty(T.Hits(d, text));

    [Fact]
    public void PlainNameColumnCountsOnlyInTables()
    {
        Assert.True(PersonNameFieldDetector.IsNameField("Name", tabular: true));
        Assert.False(PersonNameFieldDetector.IsNameField("Name", tabular: false));
    }

    [Fact]
    public void MaskKeepsInitials() => Assert.Equal("J. B.", d.Mask("Jonas Beispiel"));
}

public class LineScannerTests
{
    [Fact]
    public void IbanWinsOverDigitsInsideIt()
    {
        // The digits of an IBAN can look like a phone number or tax id: only the IBAN is reported
        Assert.Equal(["PII-IBAN"], T.Ids("DE34 8741 7522 0147 1659 35"));
    }

    [Fact]
    public void Art9FieldKeepsHitsInsideItVisible()
    {
        var ids = T.Ids("\"diagnose\": \"F32.1 seit 2024\"");
        Assert.Contains("PII-ART9-FIELD", ids);
        Assert.Contains("PII-HEALTH-ICD", ids);
    }

    [Fact]
    public void MinimumConfidenceFiltersLowHits()
    {
        Assert.Contains("PII-DE-TAXID", T.Ids("ref 86095742719", Confidence.Low));
        Assert.DoesNotContain("PII-DE-TAXID", T.Ids("ref 86095742719", Confidence.Medium));
    }

    [Fact]
    public void DetectorIdsAreUniqueAndStable()
    {
        var ids = DetectorCatalog.All.Select(d => d.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
        Assert.All(ids, id => Assert.StartsWith("PII-", id));
        Assert.Equal(12, ids.Count);
    }
}
