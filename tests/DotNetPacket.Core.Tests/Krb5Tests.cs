using DotNetPacket.Protocols.Krb5;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class Krb5Tests
{
    // AS-REQ built for roastme@LAB.LOCAL with a fixed nonce (0x11223344) and till 2026-11-07T09:00Z.
    // Confirmed by Wireshark's Kerberos dissector against the live lab KDC: krb-as-req, pvno 5,
    // pA-PAC-REQUEST, kdc-options 50800000 (forwardable/proxiable/renewable), cname roastme,
    // realm LAB.LOCAL, sname krbtgt/LAB.LOCAL, etype RC4-HMAC (23).
    private const string AsReqFixed =
        "6a81ab3081a8a103020105a20302010aa31530133011a10402020080a20904073005a0030101ffa48184" +
        "308181a00703050050800000a1143012a003020101a10b30091b07726f6173746d65a20b1b094c41422e" +
        "4c4f43414ca31e301ca003020101a11530131b066b72627467741b094c41422e4c4f43414ca511180f32" +
        "303236313130373039303030305aa611180f32303236313130373039303030305aa706020411223344a8" +
        "053003020117";

    [Fact]
    public void AsReq_Build_ReproducesTheWireBytes()
    {
        byte[] req = AsReq.Build("lab.local", "roastme", 0x11223344u,
            new DateTimeOffset(2026, 11, 7, 9, 0, 0, TimeSpan.Zero));

        Assert.Equal(AsReqFixed, Convert.ToHexString(req).ToLowerInvariant());
    }

    // Verbatim KRB-ERROR captured from the lab KDC answering the roastme AS-REQ (the Samba 4.19
    // KDC does not honour UF_DONT_REQUIRE_PREAUTH, so it demands pre-auth — same as stock impacket).
    private const string KrbErrorPreauth =
        "7e82010530820101a003020105a10302011ea411180f32303236313130363039303833385aa5050203011" +
        "8cfa603020119a70b1b094c41422e4c4f43414ca8143012a003020101a10b30091b07726f6173746d65a9" +
        "0b1b094c41422e4c4f43414caa1e301ca003020101a11530131b066b72627467741b094c41422e4c4f434" +
        "14cab2b1b294e65656420746f207573652050412d454e432d54494d455354414d502f50412d504b2d4153" +
        "2d524551ac59045730553009a103020110a20204003009a10302010fa20204003009a103020102a202040" +
        "0300aa10402020088a20204003012a103020113a20b040930073005a0030201173012a10302010ba20b04" +
        "0930073005a003020117";

    [Fact]
    public void Parse_KrbError_ExtractsPreauthRequired()
    {
        KerberosResponse r = KerberosResponse.Parse(Convert.FromHexString(KrbErrorPreauth));

        Assert.False(r.IsAsRep);
        Assert.Equal(Krb5Constants.KdcErrPreauthRequired, r.ErrorCode);
        Assert.Contains("PREAUTH_REQUIRED", Krb5Constants.DescribeError(r.ErrorCode));
    }

    // Sample enc-part cipher 0x00..0x27; the roast strings are cross-checked against impacket's
    // exact GetNPUsers format expressions.
    private static readonly byte[] SampleCipher = Enumerable.Range(0, 40).Select(i => (byte)i).ToArray();

    [Fact]
    public void AsRepRoast_Rc4_MatchesImpacketHashcatFormat()
    {
        Assert.Equal(
            "$krb5asrep$23$roastme@LAB.LOCAL:000102030405060708090a0b0c0d0e0f$" +
            "101112131415161718191a1b1c1d1e1f2021222324252627",
            AsRepRoast.Hashcat(23, "roastme", "lab.local", SampleCipher));
    }

    [Fact]
    public void AsRepRoast_Aes_MatchesImpacketHashcatFormat()
    {
        Assert.Equal(
            "$krb5asrep$18$roastme$LAB.LOCAL$1c1d1e1f2021222324252627$" +
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b",
            AsRepRoast.Hashcat(18, "roastme", "lab.local", SampleCipher));
    }

    [Fact]
    public void AsRepRoast_Rc4_John_MatchesImpacketFormat()
    {
        Assert.Equal(
            "$krb5asrep$roastme@LAB.LOCAL:000102030405060708090a0b0c0d0e0f$" +
            "101112131415161718191a1b1c1d1e1f2021222324252627",
            AsRepRoast.John(23, "roastme", "lab.local", SampleCipher));
    }

    [Fact]
    public void Parse_AsRep_RoundTripsEtypeAndCipher()
    {
        // Synthetic (NOT captured) minimal AS-REP, hand-encoded to exercise the parser: the Samba
        // lab KDC won't emit a pre-auth-less AS-REP, so there is no real capture to pin here. A
        // round-trip through a minimal encoder validates enc-part (etype 23, cipher) extraction.
        byte[] cipher = { 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02 };
        byte[] asRep = SyntheticAsRep.Build(crealm: "LAB.LOCAL", cname: "roastme", etype: 23, cipher: cipher);

        KerberosResponse r = KerberosResponse.Parse(asRep);

        Assert.True(r.IsAsRep);
        Assert.Equal(23, r.EncPartEtype);
        Assert.Equal(cipher, r.EncPartCipher);
    }
}
