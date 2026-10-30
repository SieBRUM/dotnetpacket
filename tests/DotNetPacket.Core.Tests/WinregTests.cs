using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class WinregTests
{
    // The winreg (MS-RRP) input strings are RRP_UNICODE_STRINGs: unlike the
    // RPC_UNICODE_STRINGs used elsewhere, the NUL terminator IS counted in
    // Length/MaximumLength and the conformant buffer. This exact byte shape is
    // what a detection would key on, so pin it with a known-bytes assertion.
    // Live OpenHKLM/GetVersion/OpenKey values are validated by the rpc-reg example.

    [Fact]
    public void WriteRrpUnicodeString_HasNulCountedHeaderAndBuffer()
    {
        var ndr = new NdrWriter();
        ndr.WriteRrpUnicodeString("ab");

        byte[] expected =
        {
            0x06, 0x00,             // Length = (2 chars + NUL) * 2 = 6
            0x06, 0x00,             // MaximumLength = 6
            0x00, 0x00, 0x02, 0x00, // Buffer referent (non-null)
            0x03, 0x00, 0x00, 0x00, // MaxCount = 3 (incl. NUL)
            0x00, 0x00, 0x00, 0x00, // Offset = 0
            0x03, 0x00, 0x00, 0x00, // ActualCount = 3
            0x61, 0x00, 0x62, 0x00, // "ab"
            0x00, 0x00,             // terminating NUL
            0x00, 0x00,             // Align(4) padding
        };

        Assert.Equal(expected, ndr.ToArray());
    }

    [Fact]
    public void WriteRrpUnicodeString_CountsIncludeTerminatorForTypicalSubkey()
    {
        var ndr = new NdrWriter();
        ndr.WriteRrpUnicodeString("SOFTWARE");

        byte[] bytes = ndr.ToArray();

        // "SOFTWARE" is 8 chars; counts include the NUL => 9 chars = 18 bytes.
        Assert.Equal(0x12, bytes[0]); // Length low byte = 18
        Assert.Equal(0x00, bytes[1]);
        Assert.Equal(0x12, bytes[2]); // MaximumLength low byte = 18
        Assert.Equal(0x00, bytes[3]);
        Assert.Equal(9u, System.BitConverter.ToUInt32(bytes, 8));  // MaxCount
        Assert.Equal(0u, System.BitConverter.ToUInt32(bytes, 12)); // Offset
        Assert.Equal(9u, System.BitConverter.ToUInt32(bytes, 16)); // ActualCount
    }
}
