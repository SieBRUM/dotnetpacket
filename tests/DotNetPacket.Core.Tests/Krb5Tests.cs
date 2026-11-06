using System.Text;
using DotNetPacket.Protocols.Krb5;
using DotNetPacket.Protocols.Ntlm;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class Krb5Tests
{
    // --- RC4-HMAC crypto (RFC 4757), cross-checked byte-for-byte against impacket's _RC4. ---

    [Fact]
    public void Rc4StringToKey_IsTheNtHash()
    {
        // The well-known NT hash of "password".
        Assert.Equal("8846f7eaee8fb117ad06bdd830b7586c",
            Convert.ToHexString(Krb5Crypto.Rc4StringToKey("password")).ToLowerInvariant());
    }

    [Theory]
    [InlineData(1, "11210b2aa59f7ac229d24029f93079adfdd9ff14704fcbad13261f62fba4019425dd9c0cf0a95020")]
    [InlineData(3, "95359df3832a62ddd655e06cb14dc23db14d72a0e11a9f68035f798a589833b2cc4a08261f69c192")]
    public void Encrypt_MatchesImpacketVector(int usage, string expected)
    {
        byte[] key = NtlmCrypto.NtHash("password");
        byte[] confounder = { 0, 1, 2, 3, 4, 5, 6, 7 };
        byte[] ct = Krb5Crypto.Encrypt(key, usage, Encoding.ASCII.GetBytes("hello kerberos!!"), confounder);

        Assert.Equal(expected, Convert.ToHexString(ct).ToLowerInvariant());
    }

    [Fact]
    public void Decrypt_RoundTripsEncrypt_AndRejectsWrongKey()
    {
        byte[] key = NtlmCrypto.NtHash("password");
        byte[] plaintext = Encoding.ASCII.GetBytes("round trips just fine");
        byte[] ct = Krb5Crypto.Encrypt(key, 1, plaintext, new byte[8]);

        Assert.Equal(plaintext, Krb5Crypto.Decrypt(key, 1, ct));
        Assert.Throws<InvalidDataException>(() => Krb5Crypto.Decrypt(NtlmCrypto.NtHash("wrong"), 1, ct));
    }

    // Deterministic PA-ENC-TIMESTAMP AS-REQ (Administrator@LAB.LOCAL, key=NThash("password"),
    // fixed confounder/nonce/timestamps). The live lab KDC accepts the same request shape (it
    // returned a TGT), and Wireshark decodes it as krb-as-req with PA-ENC-TIMESTAMP + PA-PAC-REQUEST.
    private const string PreauthAsReq =
        "6a81fb3081f8a103020105a20302010aa35f305d3048a103020102a241043f303da003020117a2360434" +
        "c1ad844a2fa6d4b5790047615d1ac693161e306234633bcdb08680c025b6c3a74234982c026f3b298a58" +
        "a646ebfb8d72d2281e553011a10402020080a20904073005a0030101ffa4818a308187a0070305005080" +
        "0000a11a3018a003020101a111300f1b0d41646d696e6973747261746f72a20b1b094c41422e4c4f4341" +
        "4ca31e301ca003020101a11530131b066b72627467741b094c41422e4c4f43414ca511180f3230323631" +
        "3130373039303030305aa611180f32303236313130373039303030305aa706020411223344a805300302" +
        "0117";

    [Fact]
    public void BuildPreauth_ReproducesTheWireBytes()
    {
        byte[] key = NtlmCrypto.NtHash("password");
        byte[] confounder = { 0, 1, 2, 3, 4, 5, 6, 7 };
        byte[] req = AsReq.BuildPreauth(
            "lab.local", "Administrator", key, 0x11223344u,
            till: new DateTimeOffset(2026, 11, 7, 9, 0, 0, TimeSpan.Zero),
            now: new DateTimeOffset(2026, 11, 6, 9, 0, 0, TimeSpan.Zero),
            usec: 123456, confounder: confounder);

        Assert.Equal(PreauthAsReq, Convert.ToHexString(req).ToLowerInvariant());
    }


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

    // --- TGS / Kerberoast ---

    [Fact]
    public void KerbTgsRoast_Rc4_MatchesImpacketFormat()
    {
        byte[] cipher = Enumerable.Range(0, 40).Select(i => (byte)i).ToArray();
        Assert.Equal(
            "$krb5tgs$23$*svcroast$LAB.LOCAL$MSSQLSvc/db.lab.local~1433*$" +
            "000102030405060708090a0b0c0d0e0f$101112131415161718191a1b1c1d1e1f2021222324252627",
            KerbTgsRoast.Hashcat(23, "svcroast", "lab.local", "MSSQLSvc/db.lab.local:1433", cipher));
    }

    // Deterministic TGS-REQ (fixed TGT session key / ticket stub / nonce / timestamps / confounder).
    // Includes the RFC-mandated authenticator checksum over the req-body (key usage 6) that the
    // Heimdal/Samba KDC requires — the lab KDC accepted this exact request shape and returned a TGS.
    private const string TgsReqFixed =
        "6c82013b30820137a103020105a20302010ca381c43081c13081bea103020101a281b60481b36e81b030" +
        "81ada003020105a10302010ea20703050000000000a3056103020105a4819030818da003020117a28185" +
        "048182a3066ba176959f9bcddf3730cc85a77fddd346fd5679c107a19ea159cca6aa110b0eaccc6c3526" +
        "4374fa83befdb260cc240cb9474f6653be1869d2013e808bdbe3f09b9f2d284acf700712332e4c1aa841" +
        "d6996fad23f7df65b04b8827db4f81563a1a95a944566096b45e67e6c013454b819ea6b4e6c1c0a6de35" +
        "860880a3d3a46ea4643062a00703050040810010a20b1b094c41422e4c4f43414ca3283026a003020102" +
        "a11f301d1b084d5353514c5376631b1164622e6c61622e6c6f63616c3a31343333a511180f3230323631" +
        "3130373039303030305aa706020422446688a8053003020117";

    [Fact]
    public void TgsReq_Build_ReproducesTheWireBytes()
    {
        var tgt = new Tgt(
            Ticket: Convert.FromHexString("6103020105"),
            SessionKeyEtype: 23,
            SessionKey: Convert.FromHexString("00112233445566778899aabbccddeeff"),
            EndTime: null, Realm: "LAB.LOCAL", User: "Administrator", ServiceName: "krbtgt/LAB.LOCAL");

        byte[] req = TgsReq.Build(tgt, "MSSQLSvc/db.lab.local:1433", 0x22446688u,
            till: new DateTimeOffset(2026, 11, 7, 9, 0, 0, TimeSpan.Zero),
            now: new DateTimeOffset(2026, 11, 6, 9, 0, 0, TimeSpan.Zero),
            usec: 654321, authConfounder: new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 });

        Assert.Equal(TgsReqFixed, Convert.ToHexString(req).ToLowerInvariant());
    }

    // Verbatim TGS-REP captured from the lab KDC (kerberoast of svcroast / MSSQLSvc). The
    // service-ticket enc-part is the roast material (RC4, etype 23).
    private const string TgsRepCapture =
        "6d82065e3082065aa003020105a10302010da30b1b094c41422e4c4f43414ca41a3018a003020101a111" +
        "300f1b0d41646d696e6973747261746f72a582050d6182050930820505a003020105a10b1b094c41422e" +
        "4c4f43414ca2283026a003020102a11f301d1b084d5353514c5376631b1164622e6c61622e6c6f63616c" +
        "3a31343333a38204c5308204c1a003020117a103020102a28204b3048204afe503e396367b149e0c5cb0" +
        "5353b8fa9c872d84da8081ae462b5bda7a8118c3933277ed8c78b66590a352d798e118b22cba6142923f" +
        "794c5d624fa4481020f3630c0485ccd3c37aa734a0180fda0ec316f0b5e81c80f497980935b6a1b95851" +
        "52277486d14e46edbe0fd4b096d443c19c31c381cbaaa06810043909336bec3769fa5bc042fe94452d71" +
        "37a17f7e40e8d57a1e0a0d784e33e847d4119ec5cbc2f7301d6e2fe378d0f8af4f36f2b82f11ffac07a1" +
        "99333249404200d884b00f9eb627347ae3444b2decde5ec1c52d40ae98308b54848cd08629a88d8bee2e" +
        "3268224fbd6acd12d918834ef845775428055ca6a32bbc41a8d2f7867880e9e93882337909266e47c5bd" +
        "daf03a03c2cd7385484b53f1def442f74289381bdced6e530bf550250c8345a2bd268b619af2a823c013" +
        "315b806e9db192fb13e9ab35a981b8e53238619a138b9024c296f9fac275ce80d12e1e455c43dc0070b2" +
        "024a9334e257a432e97c899323267b6e09302d92cfe70fee95c04c64a5b573ca97f37275308a90a57aa6" +
        "31731a561eb431e58f4ffa9f2573f072d28a47334db8f04f6dde9d498e8626a79fff223ce15dc0c9dacb" +
        "d227e59acaaa3e379200645162c8d6fe9d56833178e2bdda0fab596ee8717e15f7d0682121ebccdabfb0" +
        "fedd1cd46a02a4d3dce9d3ff584e7300ebffd82b0007cf184942c2aad062833a9558b28a5334a86ac0a3" +
        "5ddfb04eedaadbbff0267b3a0f0753d39c43552c035b8817a694f60e1fd020c5e9de13a648e4f9d0abae" +
        "7ae360e9383279bf677c32660c731163f41c56f01ff21fcd653f4b803a7fbecc7d07cad83e5b7f29e1b4" +
        "3c7eff858a6b2cf2a492b3a259c3ab54c2d943273446953b5e57890d9a6483d78fd710034402ad85faab" +
        "bbfd1a897a544d05aeaadbef0966dd0e56b3a3d66ac94fa2efb81a6a6433730136515b4c24533c7dbf80" +
        "a8998065b3f27b894eb2d8b95db6e1ea90d0a8cc03634064bc6d3c865d17cd92e84922156197d23ad7ea" +
        "a14d5f686946de73d49b390dd0f116b2f7f2c3b3099f3a50f108311a954748a8865aef6fde2d9fe834dc" +
        "45a2d60355929e951c117ded44707db2d8466acd20417314b2ddc56c637140b5518890e7758a4250ff98" +
        "72857679930bda798649e7f56884fab79955d675ba6a022e30579b48c8a5e1ea6122446d2cfecd11896a" +
        "c761bec4428abdff8f39cc0b7d0269cceaa309b71680ac5a12a2501e1ef8a45c0ad22500ee59b0acd02f" +
        "08e506e35dcce598fb8fb62d1fc7df583837fa771764cab62415a279a4194cf11d9161fae97d0475a37e" +
        "04bde5b6c3b5d07406267f340ec214114f627760118c1e417053a42d24176a62954b45222656245297" +
        "97d211b8d4abf6523814a14f0793670fdf4cb93d44d7edb12190642d463649ca8e70c05b6b0a6de6dfe8" +
        "10d3a2e65bb582af019837e7e30ece838e51b83b4c4d3c4df7ece9395d91e347d6150401a5d4ac507c7d" +
        "21f9b5bfae7e0eea3490b0544beae7622aba61af35e9d65c9b44a2ee2838ae329e4c933241af3d12fe34" +
        "2e20776728105ae46f3db26d293f03ca2e58329491a1a5576f8d8b2ca9693b59f530dd245e83984ebec5" +
        "7dd865c2d84a77112f78346449e4b783747ba765f775b4d714455db83b8fcd68225e92e44f23f58ef0f2" +
        "97bdb0743972abad46c542c741a68201123082010ea003020117a28201050482010133f431b0923d7bb0" +
        "d7c0ce0fa08bbeb60e2354f54b80631ea48f48aa40847b270c46e137a8031982a922e91a3a6f854292ff" +
        "c60901a226e26ad896c61062814df0e7f78fedc2b1ab7ba0e6cab5121f1a32aab5a3789f4a5f237406a6" +
        "50a8897854d0a726801c9a5d230d5f50aff0b13685a33e4ddc5a604d44cf2f10c7a2ffc8d42a4754a2ca" +
        "a70823d28adbb194692dba3915b35226eec79dbc83edf5a72cfdb5af4fbb9dd4c49f9db3f2df8fb27bc5" +
        "0ca1147a69bb7ec90df0a74422f77786ce840a29748a6fec06fbfcd030cdcd7819d0b72e8c9cd4b847de" +
        "9ba7c726308ca5e8ff371b14fe702ad9123bf0990c4185068ef7994f278541ddacf9092bbb920b";

    [Fact]
    public void TgsRep_Parse_ExtractsServiceTicketEncPart()
    {
        TgsRep r = TgsRep.Parse(Convert.FromHexString(TgsRepCapture));

        Assert.True(r.IsTgsRep);
        Assert.Equal(Krb5Constants.Rc4Hmac, r.TicketEtype);
        Assert.StartsWith("e503e396367b149e0c5cb05353b8fa9c",
            Convert.ToHexString(r.TicketCipher).ToLowerInvariant());
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
