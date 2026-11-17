using System;
using DotNetPacket.Protocols.Krb5;
using Xunit;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// Kerberos DCERPC per-message security (GSS_Wrap / GSS_GetMIC, RFC 4121 CFX) tests. The MIC is pinned
/// by a known-answer vector produced from impacket's checksum primitive (NOTE: impacket's
/// <c>GSSAPI_AES.GSS_GetMIC</c> adds a pad that is wrong for a CFX MIC token — the pad is omitted here,
/// matching what Samba's MIT-krb5 verifier accepts). The seal is checked for self-consistency against
/// the AES primitive. The full path is validated live: a Kerberos (-k) DCE-style sealed DRSUAPI bind +
/// DCSync against the lab recovers the known Administrator NT hash (see docs/PORTING_STATUS.md).
/// </summary>
public class KerberosDcerpcTests
{
    private const int Aes256 = 18;
    private static readonly byte[] Subkey =
        Convert.FromHexString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    [Fact]
    public void GetMic_MechListMic_MatchesKnownAnswer()
    {
        // MS-KRB5 MechTypeList DER (the data a SPNEGO mechListMIC is computed over).
        byte[] mechList = Convert.FromHexString("300b06092a864882f712010202");
        byte[] expected = Convert.FromHexString("040404ffffffffff0000000000000000ff55bd13f0691c751a155d91");

        var ctx = new KerberosDcerpcSecurity(Subkey, Aes256);
        Assert.Equal(expected, ctx.GetMic(mechList));
    }

    [Fact]
    public void Wrap_SealIsSelfConsistent()
    {
        // A sealed token must decrypt back to the padded plaintext under the initiator-seal usage (24),
        // after reversing the RRC+EC rotation — i.e. the token is a valid RFC 4121 CFX Wrap.
        byte[] plain = Convert.FromHexString("00112233445566778899aabbccddeeff00112233"); // 20 bytes
        byte[] confounder = Convert.FromHexString("ffffffffffffffffffffffffffffffff");

        var ctx = new KerberosDcerpcSecurity(Subkey, Aes256);
        (byte[] sealed_, byte[] signature) = ctx.Wrap(plain, confounder);

        Assert.Equal(plain.Length, sealed_.Length); // sealed body is the same length as the padded stub

        // Reconstruct and decrypt: rotated = signature[16:] + sealed; unrotate by RRC(28)+EC.
        int ec = (signature[4] << 8) | signature[5];
        int rrc = (signature[6] << 8) | signature[7];
        byte[] rotated = Concat(signature[16..], sealed_);
        byte[] cipher = Unrotate(rotated, rrc + ec);
        byte[] decrypted = Krb5Cipher.Decrypt(Aes256, Subkey, 24, cipher); // KG_USAGE_INITIATOR_SEAL

        // decrypted = plain + EC filler + 16-byte inner header.
        Assert.Equal(plain, decrypted[..plain.Length]);
        Assert.Equal(0x05, decrypted[^16]); // inner header TOK_ID high byte
        Assert.Equal(0x04, decrypted[^15]);
    }

    [Fact]
    public void Constructor_RejectsNonAes()
    {
        Assert.Throws<NotSupportedException>(() => new KerberosDcerpcSecurity(new byte[16], 23 /* RC4 */));
    }

    private static byte[] Unrotate(byte[] data, int n)
    {
        n %= data.Length;
        return Concat(data[n..], data[..n]);
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, r, 0, a.Length);
        Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
        return r;
    }
}
