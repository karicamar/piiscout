using PiiScout.Core.Detectors;

namespace PiiScout.Tests;

public class ChecksumTests
{
    [Theory]
    [InlineData("4111111111111111", true)]
    [InlineData("4597602046290718", true)]
    [InlineData("378282246310005", true)]
    [InlineData("4111111111111112", false)]
    [InlineData("79927398713", true)]  // the classic Luhn example
    [InlineData("79927398710", false)]
    [InlineData("12a4", false)]
    public void Luhn(string digits, bool valid) => Assert.Equal(valid, Checksums.Luhn(digits));

    [Theory]
    [InlineData("DE89370400440532013000", true)]
    [InlineData("DE83924884111604672105", true)]
    [InlineData("GB82WEST12345698765432", true)]
    [InlineData("FR1420041010050500013M02606", true)]
    [InlineData("AT611904300234573201", true)]
    [InlineData("DE89370400440532013001", false)] // one digit off
    [InlineData("DE8937040044053201300", false)]  // one short for DE
    [InlineData("XX89370400440532013000", false)] // unknown country
    [InlineData("DEAB370400440532013000", false)] // check digits must be digits
    public void Iban(string iban, bool valid) => Assert.Equal(valid, Checksums.Iban(iban));

    [Theory]
    [InlineData("86095742719", true)]
    [InlineData("16809624561", true)]
    [InlineData("21056979490", true)]  // one digit three times, not in a row
    [InlineData("86095742718", false)] // wrong check digit
    [InlineData("06095742719", false)] // leading zero
    [InlineData("12345678901", false)] // every digit once: no repeated digit
    [InlineData("11123456789", false)] // three in a row
    [InlineData("11223456789", false)] // two digits repeated
    [InlineData("8609574271", false)]
    public void SteuerId(string id, bool valid) => Assert.Equal(valid, Checksums.SteuerId(id));

    [Fact]
    public void SteuerIdCheckDigitIsIso7064Mod11_10() => Assert.Equal(9, Checksums.Iso7064Mod11_10("8609574271"));

    [Theory]
    [InlineData("T220001293", true)] // Mustermann specimen
    [InlineData("XT3H4M37P1", true)]
    [InlineData("T220001294", false)]
    [InlineData("A220001293", false)] // A is not in the alphabet
    [InlineData("T22000129", false)]
    public void IdCard(string number, bool valid) => Assert.Equal(valid, Checksums.IdCardNumber(number));

    [Fact]
    public void IdCardWeightsAre731() => Assert.Equal(3, Checksums.Icao7_3_1("T22000129"));

    [Theory]
    [InlineData("65170839J003", true)]
    [InlineData("77250771C010", true)]
    [InlineData("65170839J004", false)] // check digit
    [InlineData("65171339J003", false)] // month 13
    [InlineData("65000839J003", false)] // day 0
    [InlineData("651708391003", false)] // no letter
    public void SocialInsurance(string number, bool valid) => Assert.Equal(valid, Checksums.SozialversicherungsNummer(number));

    [Fact]
    public void SocialInsuranceAcceptsDayPlus50()
    {
        // Same person data as 65170839J003 but day 67 (= 17 + 50): only the check digit may differ
        var valid = Enumerable.Range(0, 10).Select(c => $"65670839J00{c}").Where(s => Checksums.SozialversicherungsNummer(s)).ToList();
        Assert.Single(valid);
    }
}
