using DotNetPacket.Protocols.Krb5;
using Xunit;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// S4U (MS-SFU) request tests. The PA-FOR-USER checksum is pinned byte-for-byte to impacket's
/// <c>_HMACMD5.checksum(key, 17, S4UByteArray)</c> (the security-critical part); the TGS-REQ shapes
/// are checked structurally (pa-data types, KDC options, additional-tickets) and validated live.
/// </summary>
public class S4uTests
{
    private static byte[] Hex(string s) => Convert.FromHexString(s);

    private static Tgt SampleTgt(int etype, byte[] key) => new(
        Ticket: Hex("6103020105"),        // minimal [APPLICATION 1] stub
        SessionKeyEtype: etype,
        SessionKey: key,
        EndTime: null,
        Realm: "LAB.LOCAL",
        User: "websvc",
        ServiceName: "krbtgt/LAB.LOCAL");

    [Theory]
    // impacket _HMACMD5.checksum(Key(etype,key), 17, LE32(1)|"Administrator"|"LAB.LOCAL"|"Kerberos").
    [InlineData("55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a", "9d040b46de2e156ccd0421de67d23e02")]
    [InlineData("ac8d0d3c9858659864b8493a51050efd", "5be0133ada2024508aa6e32af4e92281")]
    public void PaForUserChecksum_MatchesImpacket(string keyHex, string expectedHex)
    {
        byte[] s4u = System.Text.Encoding.UTF8.GetBytes("Administrator")
            .Prepend((byte)0).Prepend((byte)0).Prepend((byte)0).Prepend((byte)1).ToArray();
        s4u = s4u.Concat(System.Text.Encoding.UTF8.GetBytes("LAB.LOCAL"))
                 .Concat(System.Text.Encoding.UTF8.GetBytes("Kerberos")).ToArray();

        byte[] cksum = Krb5Crypto.Rc4HmacChecksum(Hex(keyHex), 17, s4u);
        Assert.Equal(expectedHex, Convert.ToHexString(cksum).ToLowerInvariant());
    }

    [Fact]
    public void S4u2Self_CarriesPaForUserAndSelfOptions()
    {
        Tgt tgt = SampleTgt(18, Hex("55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a"));
        byte[] req = S4uReq.BuildS4u2Self(tgt, "Administrator", "LAB.LOCAL", "websvc",
            0x11223344u, DateTimeOffset.UtcNow.AddDays(1), DateTimeOffset.UtcNow, 123, new byte[16]);

        // PA-FOR-USER pa-data type 129 (0x81) encoded as INTEGER 0x00 0x81, and the impacket checksum.
        Assert.True(Contains(req, Hex("020200 81".Replace(" ", ""))), "expected PA-FOR-USER (type 129) pa-data");
        Assert.True(Contains(req, Hex("9d040b46de2e156ccd0421de67d23e02")), "expected the PA-FOR-USER checksum");
        // S4U2self KDC-options 0x40810000.
        Assert.True(Contains(req, Hex("4081 0000".Replace(" ", ""))), "expected S4U2self KDC-options");
        // auth-package "Kerberos".
        Assert.True(Contains(req, System.Text.Encoding.ASCII.GetBytes("Kerberos")), "expected auth-package Kerberos");
    }

    [Fact]
    public void S4u2Proxy_CarriesPacOptionsAdditionalTicketAndProxyOptions()
    {
        Tgt tgt = SampleTgt(18, Hex("55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a"));
        byte[] s4uSelfTicket = Hex("6105300302 0105".Replace(" ", "")); // minimal valid [APPLICATION 1] ticket stub
        byte[] req = S4uReq.BuildS4u2Proxy(tgt, s4uSelfTicket, "cifs/target.lab.local",
            0x55667788u, DateTimeOffset.UtcNow.AddDays(1), DateTimeOffset.UtcNow, 123, new byte[16]);

        // PA-PAC-OPTIONS pa-data type 167 (0xA7) -> INTEGER 0x00 0xA7, with the RBCD flags 0x10000000.
        Assert.True(Contains(req, Hex("0202 00a7".Replace(" ", ""))), "expected PA-PAC-OPTIONS (type 167)");
        Assert.True(Contains(req, Hex("10000000")), "expected RBCD PAC-options flags");
        // S4U2proxy KDC-options 0x40830000 (adds cname-in-addl-tkt).
        Assert.True(Contains(req, Hex("40830000")), "expected S4U2proxy KDC-options");
        // The additional ticket is embedded.
        Assert.True(Contains(req, s4uSelfTicket), "expected the S4U2self ticket as an additional-ticket");
    }

    private static bool Contains(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i + needle.Length <= haystack.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }

            if (match) return true;
        }

        return false;
    }
}
