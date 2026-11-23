using DotNetPacket.Protocols.Krb5;
using Xunit;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// Golden-ticket forgery (<see cref="GoldenTicket"/> / <see cref="PacBuilder"/>). These close the loop
/// with the PAC parser/verifier: forge a TGT, then decrypt and parse it back with the *same* stack a
/// defender uses (<see cref="KerberosTicket.DecryptPac"/> + <see cref="Pac"/>), proving the ticket is a
/// well-formed, correctly-signed TGT. The PAC bytes were additionally cross-checked against impacket
/// (it parses the KERB_VALIDATION_INFO and verifies both checksums); end-to-end KDC acceptance is a
/// separate, lab-dependent matter (see docs/PORTING_STATUS.md).
/// </summary>
public class GoldenTicketTests
{
    // A throwaway lab krbtgt AES-256 key + domain SID (sample values, not a secret).
    private static readonly byte[] KrbtgtAes256 =
        Convert.FromHexString("3aa617819dbd81c9167da79602643741e68311546d7bb584ba7e5f6da5b8e8d7");
    private const string DomainSid = "S-1-5-21-3303064197-558132970-3683154743";

    [Fact]
    public void ForgedGolden_DecryptsAndVerifiesWithOurOwnStack()
    {
        ForgedTicket forged = GoldenTicket.ForgeGolden(
            "lab.local", "LAB", DomainSid, "Administrator", userRid: 500,
            KrbtgtAes256, Krb5Constants.Aes256CtsHmacSha1);

        // Pull the Ticket out of the ccache and decrypt it with the krbtgt key (the KDC's view).
        CCacheFile cc = CCache.Parse(forged.Ccache);
        byte[] ticket = cc.Credentials[0].Ticket;
        byte[]? pac = KerberosTicket.DecryptPac(ticket, KrbtgtAes256, Krb5Constants.Aes256CtsHmacSha1);
        Assert.NotNull(pac);

        // Both PAC signatures must verify under the krbtgt key (server == krbtgt for a golden TGT).
        PacVerifyResult v = Pac.Verify(pac!, KrbtgtAes256, KrbtgtAes256);
        Assert.True(v.ServerOk, "server checksum must verify");
        Assert.True(v.KdcOk == true, "KDC checksum must verify");
        Assert.Equal(16, v.ServerType); // HMAC_SHA1_96_AES256
        Assert.Equal(16, v.KdcType);

        // The forged identity must round-trip through the parser.
        PacInfo info = Pac.Parse(pac!);
        Assert.NotNull(info.LogonInfo);
        Assert.Equal("Administrator", info.LogonInfo!.EffectiveName);
        Assert.Equal(500u, info.LogonInfo.UserId);
        Assert.Equal(513u, info.LogonInfo.PrimaryGroupId);
        Assert.Equal(DomainSid, info.LogonInfo.LogonDomainSid);
        Assert.Equal(5, info.LogonInfo.Groups.Count);

        // The required modern-Samba PAC buffers are present (PAC_ATTRIBUTES_INFO 17, PAC_REQUESTOR 18).
        Assert.Contains(info.Buffers, b => b.Type == 17);
        Assert.Contains(info.Buffers, b => b.Type == 18);
    }

    [Fact]
    public void ForgedGolden_TamperedPac_FailsVerification()
    {
        ForgedTicket forged = GoldenTicket.ForgeGolden(
            "lab.local", "LAB", DomainSid, "Administrator", 500, KrbtgtAes256, Krb5Constants.Aes256CtsHmacSha1);
        byte[] ticket = CCache.Parse(forged.Ccache).Credentials[0].Ticket;
        byte[] pac = KerberosTicket.DecryptPac(ticket, KrbtgtAes256, Krb5Constants.Aes256CtsHmacSha1)!;

        // Flip a byte well inside the LOGON_INFO buffer (buffers start past the ~104-byte table):
        // the server checksum over the whole PAC must now fail.
        pac[160] ^= 0xFF;
        PacVerifyResult v = Pac.Verify(pac, KrbtgtAes256, KrbtgtAes256);
        Assert.False(v.ServerOk);
    }

    [Fact]
    public void ForgedGolden_WrongKey_DoesNotDecrypt()
    {
        ForgedTicket forged = GoldenTicket.ForgeGolden(
            "lab.local", "LAB", DomainSid, "Administrator", 500, KrbtgtAes256, Krb5Constants.Aes256CtsHmacSha1);
        byte[] ticket = CCache.Parse(forged.Ccache).Credentials[0].Ticket;

        byte[] wrongKey = new byte[32];
        Assert.ThrowsAny<Exception>(() => KerberosTicket.DecryptPac(ticket, wrongKey, Krb5Constants.Aes256CtsHmacSha1));
    }
}
