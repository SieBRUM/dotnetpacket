using DotNetPacket.Protocols.Krb5;
using DotNetPacket.Protocols.Ntlm;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class KerberosAuthTests
{
    // Standard KRB5 OID 1.2.840.113554.1.2.2 (the inner GSS mech), DER-encoded.
    private static readonly byte[] Krb5Oid = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02 };

    // MS KRB5 OID 1.2.840.48018.1.2.2 (the SPNEGO mechType), DER-encoded.
    private static readonly byte[] MsKrb5Oid = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02 };

    // SPNEGO OID 1.3.6.1.5.5.2, DER-encoded.
    private static readonly byte[] SpnegoOid = { 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02 };

    private static ServiceTicket SampleTicket() => new(
        Ticket: new byte[] { 0x61, 0x00 },               // minimal valid [APPLICATION 1] TLV
        SessionKeyEtype: 23,                             // RC4-HMAC
        SessionKey: Enumerable.Range(1, 16).Select(i => (byte)i).ToArray(),
        Realm: "LAB.LOCAL",
        User: "Administrator");

    [Fact]
    public void BuildApReqToken_IsGssFramedKerberosApReq()
    {
        KerberosApReq apReq = KerberosGss.BuildApReqToken(SampleTicket());

        // GSS-API InitialContextToken: [APPLICATION 0] (0x60) { krb5-OID, TOK_ID 0x0001, AP-REQ }.
        Assert.Equal(0x60, apReq.GssToken[0]);
        Assert.True(Contains(apReq.GssToken, Krb5Oid), "GSS token must carry the standard KRB5 OID");
        // TOK_ID 0x01 0x00 immediately follows the OID.
        int oidAt = IndexOf(apReq.GssToken, Krb5Oid);
        Assert.Equal(0x01, apReq.GssToken[oidAt + Krb5Oid.Length]);
        Assert.Equal(0x00, apReq.GssToken[oidAt + Krb5Oid.Length + 1]);
        // The AP-REQ application tag [APPLICATION 14] = 0x6E appears after the token id.
        Assert.True(Contains(apReq.GssToken, new byte[] { 0x6E }), "expected an AP-REQ ([APPLICATION 14]) body");

        // The SMB session key is the service session key (RC4, 16 bytes).
        Assert.Equal(SampleTicket().SessionKey, apReq.SessionKey);
        Assert.Equal(23, apReq.SessionKeyEtype);
    }

    [Fact]
    public void WrapKerberosInitialToken_IsSpnegoOfferingMsKrb5()
    {
        KerberosApReq apReq = KerberosGss.BuildApReqToken(SampleTicket());
        byte[] spnego = Spnego.WrapKerberosInitialToken(apReq.GssToken);

        Assert.Equal(0x60, spnego[0]);                                   // GSS-API [APPLICATION 0]
        Assert.True(Contains(spnego, SpnegoOid), "must carry the SPNEGO OID");
        Assert.True(Contains(spnego, MsKrb5Oid), "mechTypes must offer MS KRB5");
        Assert.True(Contains(spnego, apReq.GssToken), "the mechToken must be the GSS AP-REQ token");
    }

    [Fact]
    public void EtypeInfo2_ParsesAes256SaltFromMethodData()
    {
        // impacket-encoded METHOD-DATA: one PA-ETYPE-INFO2 entry, etype 18, salt "LAB.LOCALAdministrator".
        byte[] methodData = Convert.FromHexString(
            "302e302ca103020113a22504233021301fa003020112a1181b164c41422e4c4f43414c41646d696e6973747261746f72");

        var entries = EtypeInfo2.Parse(methodData);
        Assert.Single(entries);
        Assert.Equal(18, entries[0].Etype);
        Assert.Equal("LAB.LOCALAdministrator", entries[0].SaltText);
        Assert.Equal(AesCtsCrypto.DefaultIterations, entries[0].Iterations); // no s2kparams -> RFC default
    }

    [Fact]
    public void KerberosApRep_ExtractsAcceptorSubkey()
    {
        // impacket-encoded GSS AP-REP token: EncAPRepPart (usage 12) carrying a known AES-256 subkey,
        // encrypted under the ticket session key. Proves the mutual-auth SMB session-key recovery.
        byte[] gssApRep = Convert.FromHexString(
            "60819406092a864886f71201020202006f8184308181a003020105a10302010fa2753073a003020112a26c046a" +
            "c41b8f62f4e013456972479131d216241285fbcc067c09084e573b75a3fdf171072d7a977f8585491e8c764725" +
            "876c186442fb522c42c290ff4c4848213f7cc3d9b59ecbb1d5bb4087beeddc894741acf9f447895f79af2267ea" +
            "815da20e4f6b4c01e16775fa9b9db00c");
        byte[] ticketSessionKey = Convert.FromHexString(
            "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a");

        KerberosSubkey? subkey = KerberosApRep.ExtractSubkey(gssApRep, ticketSessionKey, 18);
        Assert.NotNull(subkey);
        Assert.Equal(18, subkey!.Etype);
        Assert.Equal("0011223344556677889900aabbccddee0011223344556677889900aabbccddee",
            Convert.ToHexString(subkey.Key).ToLowerInvariant());
    }

    private static bool Contains(byte[] haystack, byte[] needle) => IndexOf(haystack, needle) >= 0;

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i + needle.Length <= haystack.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }

            if (match) return i;
        }

        return -1;
    }
}
