using DotNetPacket.Core.Diagnostics;
using Xunit;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// The opt-in wire-trace facility (<see cref="PacketTrace"/>) the CLI's -verbose/-debug flags drive.
/// These pin the level gating (Off emits nothing, Verbose emits summaries, Debug adds hex) and the
/// level parser, so the global flags keep behaving as documented.
/// </summary>
public class PacketTraceTests : IDisposable
{
    private readonly TraceLevel _savedLevel = PacketTrace.Level;
    private readonly TextWriter _savedOut = PacketTrace.Out;
    private readonly StringWriter _sink = new();

    public PacketTraceTests() => PacketTrace.Out = _sink;

    public void Dispose()
    {
        PacketTrace.Level = _savedLevel;
        PacketTrace.Out = _savedOut;
    }

    [Fact]
    public void Off_EmitsNothing()
    {
        PacketTrace.Level = TraceLevel.Off;
        PacketTrace.Event("smb", "connected");
        PacketTrace.Sent("smb", new byte[] { 0x01, 0x02 });
        PacketTrace.Received("smb", new byte[] { 0x03 });
        Assert.Equal(string.Empty, _sink.ToString());
    }

    [Fact]
    public void Verbose_EmitsSummaries_NoHex()
    {
        PacketTrace.Level = TraceLevel.Verbose;
        PacketTrace.Event("ldap", "bind ok");
        PacketTrace.Sent("ldap", new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });

        string outp = _sink.ToString();
        Assert.Contains("[trace ldap] bind ok", outp);
        Assert.Contains("[trace ldap] --> 4 bytes", outp);
        // No hex dump at Verbose: the bytes must not appear as a hex row.
        Assert.DoesNotContain("de ad be ef", outp);
    }

    [Fact]
    public void Debug_AddsHexDump()
    {
        PacketTrace.Level = TraceLevel.Debug;
        PacketTrace.Received("krb5", new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });

        string outp = _sink.ToString();
        Assert.Contains("[trace krb5] <-- 4 bytes", outp);
        Assert.Contains("de ad be ef", outp); // Hex.Dump row
    }

    [Theory]
    [InlineData("off", TraceLevel.Off)]
    [InlineData("none", TraceLevel.Off)]
    [InlineData("debug", TraceLevel.Debug)]
    [InlineData("2", TraceLevel.Debug)]
    [InlineData("verbose", TraceLevel.Verbose)]
    [InlineData("", TraceLevel.Verbose)]
    [InlineData(null, TraceLevel.Verbose)]
    public void ParseLevel_MapsNames(string? value, TraceLevel expected)
    {
        Assert.Equal(expected, PacketTrace.ParseLevel(value));
    }
}
