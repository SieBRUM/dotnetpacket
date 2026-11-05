using DotNetPacket.Protocols.Gpp;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class GppCryptoTests
{
    // GPP cpassword ciphertexts produced with Microsoft's published [MS-GPPREF] key and fixed
    // zero IV, each cross-verified against impacket's decrypt_password. The key is public by
    // design, so these are deterministic protocol vectors, not secrets.
    [Theory]
    [InlineData("WcX4PUgWFt3b0e6WNWY69w==", "Local*8")]
    [InlineData("Xpk4DyKDjYQQ/EUHClHlPxfxdtbC4AQ9oD06U0tUX48=", "Passw0rd!Lab")]
    // The canonical vector quoted across GPP writeups (tests the '=' re-padding path):
    [InlineData("j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw", "Local*P4ssword!")]
    // A longer value whose base64 needs re-padding (ends without '='):
    [InlineData("PfhipLCUcMZ8J4lFTU4bewk0eKLPeNZJKL/WrTT2N4tg/Fln6uTnLzuGQ9xOitt+", "S0mething_long_er_42!")]
    public void DecryptCpassword_RecoversPlaintext(string cpassword, string expected)
    {
        Assert.Equal(expected, GppCrypto.DecryptCpassword(cpassword));
    }

    [Fact]
    public void DecryptCpassword_EmptyInput_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, GppCrypto.DecryptCpassword(string.Empty));
    }

    [Fact]
    public void Parse_GroupsXml_ExtractsUserNameAndDecryptedPassword()
    {
        // A minimal Groups.xml as GPP stores it in SYSVOL (userName + cpassword on <Properties>,
        // "changed" on the parent <User>). cpassword here decrypts to "Local*8".
        const string xml =
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
            "<Groups clsid=\"{3125E937-EB16-4b4c-9934-544FC6D24D26}\">" +
            "<User clsid=\"{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}\" name=\"Administrator (built-in)\"" +
            " changed=\"2015-02-10 09:15:23\">" +
            "<Properties action=\"U\" newName=\"\" fullName=\"\" description=\"\"" +
            " cpassword=\"WcX4PUgWFt3b0e6WNWY69w==\" userName=\"Administrator (built-in)\"/>" +
            "</User></Groups>";

        IReadOnlyList<GppFinding> findings = GppPreferences.Parse(@"Policies\{GUID}\Groups.xml", xml);

        GppFinding f = Assert.Single(findings);
        Assert.Equal("Groups", f.Type);
        Assert.Equal("Administrator (built-in)", f.UserName);
        Assert.Equal("Local*8", f.Password);
        Assert.Equal("2015-02-10 09:15:23", f.Changed);
    }

    [Fact]
    public void Parse_NoCpassword_ReturnsNothing()
    {
        const string xml = "<Groups><User name=\"x\"><Properties userName=\"x\"/></User></Groups>";
        Assert.Empty(GppPreferences.Parse("Groups.xml", xml));
    }
}
