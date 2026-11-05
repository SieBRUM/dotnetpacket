using System.Text;
using DotNetPacket.Protocols.Ntlm;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class NtlmChallengeInfoTests
{
    // Verbatim NTLMSSP CHALLENGE (Type 2) captured from an anonymous SMB2 SESSION_SETUP
    // against the lab Samba AD DC (the DumpNTLMInfo.py recon path). This is the server's
    // response bytes, unmodified — the host/OS fields the tool reports are decoded from it.
    private const string Challenge =
        "4e544c4d53535000020000000600060038000000158289a2b6b5ea376c44d66d00000000000000005400" +
        "54003e000000060100000000000f4c0041004200020006004c00410042000100040056004d0004001200" +
        "6c00610062002e006c006f00630061006c000300180076006d002e006c00610062002e006c006f006300" +
        "61006c00070008004c303a3a3b6ddd0100000000";

    [Fact]
    public void Parse_ExposesServerChallengeAndOsVersion()
    {
        NtlmChallenge c = NtlmChallenge.Parse(Convert.FromHexString(Challenge));

        Assert.Equal("b6b5ea376c44d66d", Convert.ToHexString(c.ServerChallenge).ToLowerInvariant());

        // The server disclosed its OS version block (NEGOTIATE_VERSION): Samba reports 6.1 build 0.
        Assert.True(c.HasVersion);
        Assert.Equal(6, c.OsMajor);
        Assert.Equal(1, c.OsMinor);
        Assert.Equal(0, c.OsBuild);
    }

    [Fact]
    public void TargetInfo_YieldsHostAndDnsNames()
    {
        NtlmChallenge c = NtlmChallenge.Parse(Convert.FromHexString(Challenge));
        AvPairs av = AvPairs.Parse(c.TargetInfo);

        static string? Utf16(byte[]? v) => v is null ? null : Encoding.Unicode.GetString(v);

        Assert.Equal("VM", Utf16(av.Get(NtlmAvId.NbComputerName)));
        Assert.Equal("LAB", Utf16(av.Get(NtlmAvId.NbDomainName)));
        Assert.Equal("lab.local", Utf16(av.Get(NtlmAvId.DnsDomainName)));
        Assert.Equal("vm.lab.local", Utf16(av.Get(NtlmAvId.DnsComputerName)));

        // Samba did not include a DNS tree name (AV id 5); the tool must skip that line.
        Assert.Null(av.Get(NtlmAvId.DnsTreeName));

        // A timestamp AV pair (id 7) is present.
        Assert.NotNull(av.Get(NtlmAvId.Timestamp));
    }
}
