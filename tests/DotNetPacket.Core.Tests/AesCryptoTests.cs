using System.Security.Cryptography;
using DotNetPacket.Protocols.Krb5;
using Xunit;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// AES-CTS-HMAC-SHA1-96 (RFC 3962) known-answer tests. The n-fold and string-to-key vectors are
/// pinned to the MIT krb5 reference / RFC 3962 Appendix B; the encrypt and checksum vectors are
/// pinned to stock impacket (<c>impacket.krb5.crypto</c>) with a fixed confounder, so the .NET port
/// is proven byte-for-byte against the oracle it must match on the wire.
/// </summary>
public class AesCryptoTests
{
    private static byte[] Hex(string s) => Convert.FromHexString(s);

    private static readonly byte[] FixedConfounder = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();

    [Theory]
    // RFC 3961 n-fold vectors, confirmed against the MIT krb5 reference and impacket's _nfold.
    [InlineData("303132333435363738", 64, "a928a426e3e36b30")]               // "012345678"
    [InlineData("70617373776f7264", 56, "78a07b6caf85fa")]                   // "password"
    [InlineData("6b65726265726f73", 128, "6b65726265726f737b9b5b2b93132b93")] // "kerberos" (the DK base constant)
    public void Nfold_MatchesReference(string inputHex, int outBits, string expectedHex)
    {
        byte[] result = AesCtsCrypto.Nfold(Hex(inputHex), outBits / 8);
        Assert.Equal(expectedHex, Convert.ToHexString(result).ToLowerInvariant());
    }

    [Theory]
    // RFC 3962 Appendix B: pass="password", salt="ATHENA.MIT.EDUraeburn", iter=1200.
    [InlineData(16, "4c01cd46d632d01e6dbe230a01ed642a")]
    [InlineData(32, "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a")]
    public void StringToKey_MatchesRfc3962(int keySize, string expectedHex)
    {
        byte[] salt = System.Text.Encoding.ASCII.GetBytes("ATHENA.MIT.EDUraeburn");
        byte[] key = AesCtsCrypto.StringToKey("password", salt, 1200, keySize);
        Assert.Equal(expectedHex, Convert.ToHexString(key).ToLowerInvariant());
    }

    [Theory]
    // impacket oracle: e.encrypt(Key(raw), usage, pt) with confounder 00 01 .. 0f.
    // AES-128 (etype 17).
    [InlineData("b2de129c7a76bd2c553d1caea050698a", 1, "68656c6c6f206b65726265726f7320616573",
        "c6b2d6bb1202a2898e458c13ae64898d9b88aef6d2a9dd51d4f559afab282b9a4e355fb81905a6f70fbacaeb501f")]
    [InlineData("b2de129c7a76bd2c553d1caea050698a", 3, "61732d72657020656e632d706172742073616d706c65",
        "2024134fdeb66f600b5dbc05befbda5f4110a721e0e4f972ba83e5f536ce65b9d12180896b8e7e627170612b248611cae409")]
    [InlineData("b2de129c7a76bd2c553d1caea050698a", 11, "41502d5245512061757468656e74696361746f722073616d706c65207061796c6f61642058595a",
        "1da97de718c1aee008cd65cc4b4c976c533b4247a98ab62425675f3b2224ff051454fb237b50da9691acba7d0777e5f516b07591876de6fd912ae1fb2a6b571344a7f5")]
    // AES-256 (etype 18).
    [InlineData("55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a", 1, "68656c6c6f206b65726265726f7320616573",
        "9d0b4d2529efe3d22d3b90d7a67cac72017cf689477698122dff46f599014937f8f71e003171a228117392d4cad1")]
    [InlineData("55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a", 3, "61732d72657020656e632d706172742073616d706c65",
        "2314b622283824a5f14db74c9027841747518074e19cc45b9ca79ec7127cf730630d78339b5ab2e10ff7fec85f3bc968794b")]
    [InlineData("55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a", 11, "41502d5245512061757468656e74696361746f722073616d706c65207061796c6f61642058595a",
        "da1eacf4bedacd7058bd532c9dac540e19219aa704fed607a134daa7ce589cc171df219b323dd8e5fd9066ff3d6c219408c9a7743c0d4b92eec9885ccb62c56f54417b")]
    public void Encrypt_MatchesImpacket(string keyHex, int usage, string plaintextHex, string expectedCipherHex)
    {
        byte[] ct = AesCtsCrypto.Encrypt(Hex(keyHex), usage, Hex(plaintextHex), FixedConfounder);
        Assert.Equal(expectedCipherHex, Convert.ToHexString(ct).ToLowerInvariant());

        // And it must round-trip back to the plaintext.
        byte[] pt = AesCtsCrypto.Decrypt(Hex(keyHex), usage, ct);
        Assert.Equal(plaintextHex, Convert.ToHexString(pt).ToLowerInvariant());
    }

    [Theory]
    [InlineData("b2de129c7a76bd2c553d1caea050698a", "ff8e65e47a4032960c4868f0")]
    [InlineData("55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a", "22bbf2eb1fcca25518cd2dee")]
    public void Checksum_MatchesImpacket(string keyHex, string expectedHex)
    {
        byte[] text = System.Text.Encoding.ASCII.GetBytes("req-body-bytes-sample");
        byte[] mac = AesCtsCrypto.Checksum(Hex(keyHex), 6, text);
        Assert.Equal(expectedHex, Convert.ToHexString(mac).ToLowerInvariant());
    }

    [Theory]
    // Exercise every CTS length regime: exactly one block (confounder only), exact 2-block multiple,
    // and partial trailing blocks of several sizes.
    [InlineData(0)]   // data = 16 (single block, no stealing)
    [InlineData(16)]  // data = 32 (exact multiple, last-two swap, lastlen = 16)
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(17)]
    [InlineData(100)]
    public void EncryptDecrypt_RoundTrips(int plaintextLen)
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] pt = RandomNumberGenerator.GetBytes(plaintextLen);
        byte[] ct = AesCtsCrypto.Encrypt(key, 7, pt, null);
        Assert.Equal(pt, AesCtsCrypto.Decrypt(key, 7, ct));
    }
}
