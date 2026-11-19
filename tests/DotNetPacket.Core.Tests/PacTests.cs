using System;
using System.Linq;
using DotNetPacket.Protocols.Krb5;
using Xunit;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// MS-PAC parser tests. The fixture is a real PAC captured from the lab (Administrator's PAC out of an
/// S4U2self service ticket, see docs/PORTING_STATUS.md) and every asserted field was cross-verified
/// byte-for-byte against impacket's <c>krb5.pac</c> VALIDATION_INFO parser (scratchpad/pac_oracle.py).
/// Lab/sample values only: the throwaway lab's domain SID and account names, no reusable secret (the
/// PAC's checksums are per-ticket HMACs, not a key).
/// </summary>
public class PacTests
{
    private const string PacHex =
        "0800000000000000010000002802000088000000000000000d00000000000000b0020000000000000a00000024000000b0020000000000000c00000098000000d8020000000000000600000014000000700300000000000007000000100000008803000000000000100000001000000098030000000000001300000010000000a80300000000000001100800cccccccc180200000000000000000200aee9d37a9077dd01ffffffffffffff7fffffffffffffff7f187f622a8068dd01187f622a8068dd0118ffbb1f8189dd011a001a00040002000000000008000200000000000c00020000000000100002000000000014000200000000001800020048000000f401000001020000050000001c0002002002000000000000000000000000000000000000040006002000020006000800240002002800020000000000000000001000000000000000000000000000000000000000000000000000000000000000020000002c0002003000020001000000340002000d000000000000000d000000410064006d0069006e006900730074007200610074006f0072000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000050000000102000007000000000200000700000006020000070000000702000007000000080200000700000003000000000000000200000056004d000400000000000000030000004c004100420000000400000001040000000000051500000085c2e0c4ea6e4421377b88db0200000038000200070000003c000200070000000100000001010000000000120200000005000000010500000000000515000000000000000000000000000000f10100000400000001040000000000051500000085c2e0c4ea6e4421377b88db010000003c020000070000208096331b5278dd011a00410064006d0069006e006900730074007200610074006f007200000000002e00180012004800030000001a0060001c007a0000000000410064006d0069006e006900730074007200610074006f00720040006c00610062002e006c006f00630061006c0000004c00410042002e004c004f00430041004c00000000000000410064006d0069006e006900730074007200610074006f00720001050000000000051500000085c2e0c4ea6e4421377b88dbf4010000000076ffffffe91c5c517824acfbd11c303842c15d94000000001000000029592163a646437ad756d37a10000000aed772c649631db1c7c11d81100000003d6598f6d9fbabd1ab98fb5b";

    [Fact]
    public void Parse_LogonInfo_MatchesImpacketOracle()
    {
        PacInfo pac = Pac.Parse(Convert.FromHexString(PacHex));

        Assert.Equal(8, pac.Buffers.Count);
        Assert.NotNull(pac.LogonInfo);
        PacLogonInfo li = pac.LogonInfo!;

        Assert.Equal("Administrator", li.EffectiveName);
        Assert.Equal(500u, li.UserId);                 // Administrator RID
        Assert.Equal(513u, li.PrimaryGroupId);         // Domain Users
        Assert.Equal(0x10u, li.UserAccountControl);
        Assert.Equal(0x220u, li.UserFlags);
        Assert.Equal("LAB", li.LogonDomainName);
        Assert.Equal("VM", li.LogonServer);
        Assert.Equal("S-1-5-21-3303064197-558132970-3683154743", li.LogonDomainSid);

        // Domain Users/Admins, Schema/Enterprise Admins, Group Policy Creator Owners.
        Assert.Equal(new uint[] { 513, 512, 518, 519, 520 }, li.Groups.Select(g => g.Rid).ToArray());

        Assert.Equal(new[] { "S-1-18-2", "S-1-5-21-0-0-0-497" }, li.ExtraSids.ToArray());
    }

    // svcroast's RC4/NT hash (server-checksum key) and krbtgt's AES-256 key (KDC-checksum key), both
    // recovered via DCSync earlier in the project — lab/sample values for a throwaway lab.
    private const string SvcroastNtHash = "7cd13d90d3cb835ab9c08ac18edeea2b";
    private const string KrbtgtAes256 = "3aa617819dbd81c9167da79602643741e68311546d7bb584ba7e5f6da5b8e8d7";

    [Fact]
    public void Verify_GenuineSignatures_BothValid()
    {
        byte[] pac = Convert.FromHexString(PacHex);
        PacVerifyResult v = Pac.Verify(pac, Convert.FromHexString(SvcroastNtHash), Convert.FromHexString(KrbtgtAes256));
        Assert.Equal(-138, v.ServerType); // KERB_CHECKSUM_HMAC_MD5
        Assert.Equal(16, v.KdcType);      // HMAC_SHA1_96_AES256
        Assert.True(v.ServerOk);
        Assert.True(v.KdcOk);
    }

    [Fact]
    public void Verify_TamperedLogonInfo_ServerChecksumFails()
    {
        // Flip a byte inside the LOGON_INFO buffer (offset 136): a forged/edited PAC must fail the
        // server checksum — the core forged-PAC (golden-ticket) detection.
        byte[] pac = Convert.FromHexString(PacHex);
        pac[200] ^= 0xFF;
        PacVerifyResult v = Pac.Verify(pac, Convert.FromHexString(SvcroastNtHash), Convert.FromHexString(KrbtgtAes256));
        Assert.False(v.ServerOk);
    }

    [Fact]
    public void Parse_ClientInfoUpnAndChecksums()
    {
        PacInfo pac = Pac.Parse(Convert.FromHexString(PacHex));

        Assert.Equal("Administrator", pac.ClientInfo!.Name);
        Assert.Equal("Administrator@lab.local", pac.UpnDnsInfo!.Upn);
        Assert.Equal("LAB.LOCAL", pac.UpnDnsInfo!.DnsDomainName);

        Assert.Equal(-138, pac.ServerChecksum!.Type); // KERB_CHECKSUM_HMAC_MD5 (RC4 ticket)
        Assert.Equal(16, pac.ServerChecksum!.Signature.Length);
        Assert.Equal(16, pac.KdcChecksum!.Type);      // HMAC_SHA1_96_AES256 (krbtgt AES key)
        Assert.Equal(12, pac.KdcChecksum!.Signature.Length);
    }
}
