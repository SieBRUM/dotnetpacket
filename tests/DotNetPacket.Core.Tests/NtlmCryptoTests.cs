using System.Text;
using DotNetPacket.Protocols.Ntlm;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class NtlmCryptoTests
{
    private static byte[] Hex(string hex) => Convert.FromHexString(hex);

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    // RFC 1320 Appendix A.5 MD4 test vectors.
    [Theory]
    [InlineData("", "31d6cfe0d16ae931b73c59d7e0c089c0")]
    [InlineData("a", "bde52cb31de33e46245e05fbdbd6fb24")]
    [InlineData("abc", "a448017aaf21d8525fc10ae87aa6729d")]
    [InlineData("message digest", "d9130a8164549fe818874806e1c7014b")]
    public void Md4_MatchesRfc1320(string input, string expected)
    {
        Assert.Equal(expected, Hex(NtlmCrypto.Md4(Encoding.ASCII.GetBytes(input))));
    }

    // RFC 2202 §2 HMAC-MD5 test case 1.
    [Fact]
    public void HmacMd5_MatchesRfc2202()
    {
        byte[] key = Enumerable.Repeat((byte)0x0b, 16).ToArray();
        byte[] mac = NtlmCrypto.HmacMd5(key, Encoding.ASCII.GetBytes("Hi There"));
        Assert.Equal("9294727a3638bb1c13f48ef8158bfc9d", Hex(mac));
    }

    // RC4 is symmetric: decrypt(encrypt(x)) == x; and a known test vector (key "Key", "Plaintext").
    [Fact]
    public void Rc4_KnownVector()
    {
        byte[] ct = NtlmCrypto.Rc4(Encoding.ASCII.GetBytes("Key"), Encoding.ASCII.GetBytes("Plaintext"));
        Assert.Equal("bbf316e8d940af0ad3", Hex(ct));
    }

    [Fact]
    public void Rc4_RoundTrips()
    {
        byte[] key = Hex("0123456789abcdef0123456789abcdef");
        byte[] plain = Encoding.ASCII.GetBytes("the quick brown fox");
        byte[] roundTrip = NtlmCrypto.Rc4(key, NtlmCrypto.Rc4(key, plain));
        Assert.Equal(plain, roundTrip);
    }

    // MS-NLMP 4.2.4.1: with User="User", Domain="Domain", Password="Password",
    // NTOWFv2 = 0c868a403bfd7a93a3001ef22ef02e3f.
    [Fact]
    public void NtowfV2_MatchesMsNlmpVector()
    {
        byte[] ntowf = NtlmCrypto.NtowfV2("Password", "User", "Domain");
        Assert.Equal("0c868a403bfd7a93a3001ef22ef02e3f", Hex(ntowf));
    }
}
