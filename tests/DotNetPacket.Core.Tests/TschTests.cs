using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class TschTests
{
    // These stubs were checked byte-for-byte against impacket's tsch encoder for the same inputs
    // (path "\ABC", xml "<Task/>"); they match except for DotNetPacket's documented choices:
    // MIDL-style referent ids (0x00020000+) vs impacket's random ids, and zero-filled NDR pad
    // vs impacket's 0xAB/0xBF fill. Structure (field order/types/lengths) is identical.

    [Fact]
    public void EncodeRegisterTask_MatchesExpectedNdr()
    {
        byte[] stub = Tsch.EncodeRegisterTask("\\ABC", "<Task/>", Tsch.TaskCreate, Tsch.TaskLogonNone);
        const string expected =
            "00000200" +                                   // path LPWSTR referent (present)
            "0500000000000000050000005c00410042004300" +   // path "\ABC\0" (max/off/actual + chars)
            "00000000" +                                   // "...43 00 00" tail + align pad (zero-fill)
            "0800000000000000080000003c005400610073006b002f003e000000" + // xml "<Task/>\0"
            "02000000" +                                   // flags = TASK_CREATE
            "00000000" +                                   // sddl = NULL
            "00000000" +                                   // logonType = TASK_LOGON_NONE
            "00000000" +                                   // cCreds = 0
            "00000000";                                    // pCreds = NULL
        Assert.Equal(expected, Convert.ToHexString(stub).ToLowerInvariant());
    }

    [Theory]
    [InlineData("run")]
    [InlineData("delete")]
    [InlineData("getlast")]
    public void Encode_SimpleCalls_MatchExpectedNdr(string which)
    {
        (byte[] stub, string expected) = which switch
        {
            "run" => (Tsch.EncodeRun("\\ABC"),
                "0500000000000000050000005c00410042004300000000000000000000000000000000000000000000000000"),
            "delete" => (Tsch.EncodeDelete("\\ABC"),
                "0500000000000000050000005c004100420043000000000000000000"),
            _ => (Tsch.EncodeGetLastRunInfo("\\ABC"),
                "0500000000000000050000005c0041004200430000000000"),
        };

        Assert.Equal(expected, Convert.ToHexString(stub).ToLowerInvariant());
    }

    [Fact]
    public void BuildTaskXml_EmbedsCommandAndArguments_Escaped()
    {
        string xml = Tsch.BuildTaskXml("cmd.exe", "/C whoami > out.tmp 2>&1");

        Assert.Contains("<Command>cmd.exe</Command>", xml);
        Assert.Contains("<Arguments>/C whoami &gt; out.tmp 2&gt;&amp;1</Arguments>", xml); // XML-escaped
        Assert.Contains("<UserId>S-1-5-18</UserId>", xml);   // runs as LocalSystem
        Assert.Contains("<Hidden>true</Hidden>", xml);
    }
}
