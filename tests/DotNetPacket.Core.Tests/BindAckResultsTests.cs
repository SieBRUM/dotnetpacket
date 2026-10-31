using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class BindAckResultsTests
{
    // A real BIND_ACK captured from a Samba AD DC answering a two-context bind
    // (ctx0 = NDR, ctx1 = NDR64) — the getarch probe. ctx0 is accepted; ctx1 is
    // rejected with provider_rejection / reason 2 (transfer syntaxes not supported),
    // which is how a non-x64 / non-Windows stack answers the NDR64 offer. The live
    // rpc-getarch example drives the probe; this pins the result-list parse.
    private const string DualContextBindAck =
        "05000c0310000000" + "5400" + "0000" + "01000000" + // header: BIND_ACK, frag_len 0x54, call_id 1
        "b810b810" + "54090000" +                            // max_xmit/recv, assoc_group
        "0400" + "31333500" + "0000" +                       // sec_addr "135\0", pad to 4
        "02000000" +                                         // n_results = 2 (+ reserved)
        "0000" + "0000" + "045d888aeb1cc9119fe808002b104860" + "02000000" + // ctx0: Acceptance, NDR
        "0200" + "0200" + "00000000000000000000000000000000" + "00000000";  // ctx1: ProviderRejection/2, null syntax

    [Fact]
    public void Parse_ReadsBothContextResults()
    {
        DcerpcBindAck ack = DcerpcBindAck.Parse(Convert.FromHexString(DualContextBindAck));

        Assert.Equal(2, ack.Results.Count);
        Assert.Equal(DcerpcBindAck.ContextResult.Acceptance, ack.Results[0].Result);
        Assert.Equal(DcerpcBindAck.ContextResult.ProviderRejection, ack.Results[1].Result);
        Assert.Equal(2, ack.Results[1].Reason); // proposed_transfer_syntaxes_not_supported
    }

    [Fact]
    public void Parse_Ndr64Rejected_MeansNotX64()
    {
        DcerpcBindAck ack = DcerpcBindAck.Parse(Convert.FromHexString(DualContextBindAck));

        bool ndr64Accepted = ack.Results.Count >= 2
            && ack.Results[1].Result == DcerpcBindAck.ContextResult.Acceptance;
        Assert.False(ndr64Accepted); // Samba rejects NDR64
    }
}
