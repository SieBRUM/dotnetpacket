using System.Net.Sockets;
using DotNetPacket.Core;
using DotNetPacket.Transport;

namespace DotNetPacket.Protocols.Smb;

/// <summary>
/// A one-shot SMBv1 NEGOTIATE used only to detect whether a server still speaks SMB1.
/// Port of impacket <c>DumpNTLMInfo.py</c>'s <c>IsSmb1Enabled</c>: it sends a legacy
/// SMB_COM_NEGOTIATE offering a single dialect, "NT LM 0.12", and reports whether the
/// server answers with an SMB1 response. A modern (SMB2-only) server resets, times out,
/// or answers with the SMB2 signature instead — all read as "SMB1 disabled".
/// </summary>
/// <remarks>
/// This is the one place the port speaks SMB1 on purpose: it is a detection probe against
/// the target, not the client's own session path (which stays SMB2/3; see docs/REALISM.md).
/// It is split out here so the SMB1 bytes never leak into the realistic SMB2 client.
/// </remarks>
public static class Smb1NegotiateProbe
{
    // The lone legacy dialect offered: 0x02 (dialect buffer-format marker) + "NT LM 0.12" + NUL.
    private static readonly byte[] NtLm012Dialect =
    {
        0x02, (byte)'N', (byte)'T', (byte)' ', (byte)'L', (byte)'M', (byte)' ',
        (byte)'0', (byte)'.', (byte)'1', (byte)'2', 0x00,
    };

    /// <summary>
    /// Returns true if <paramref name="host"/>:<paramref name="port"/> answers an SMBv1
    /// NEGOTIATE with an SMB1 response (i.e. SMB1 is enabled). Any reset / timeout / non-SMB1
    /// reply is treated as disabled.
    /// </summary>
    public static bool IsEnabled(string host, int port = 445, int timeoutMs = 10_000)
    {
        try
        {
            using var transport = new DirectTcpTransport();
            transport.Connect(host, port, timeoutMs);
            transport.SendMessage(BuildNegotiate());
            byte[] response = transport.ReceiveMessage(timeoutMs);

            // An SMB1 reply starts with 0xFF 'S' 'M' 'B' and echoes command 0x72 (NEGOTIATE).
            return response.Length >= 5
                && response[0] == 0xFF && response[1] == (byte)'S'
                && response[2] == (byte)'M' && response[3] == (byte)'B'
                && response[4] == 0x72;
        }
        catch (Exception ex) when (ex is IOException or SocketException or TimeoutException or EndOfStreamException)
        {
            // Connection reset / no answer: SMB1 is not served.
            return false;
        }
    }

    private static byte[] BuildNegotiate()
    {
        // Flags/Flags2 of a modern client probe: caseless + canonicalized paths; extended
        // security + NT status + unicode + long names (matches the probe's wildcard negotiate).
        var header = new SmbHeader
        {
            Command = 0x72, // SMB_COM_NEGOTIATE
            Flags = 0x18,
            Flags2 = 0xC853,
            Mid = 1,
        };

        var body = new ByteWriter(ByteOrder.Little);
        body.WriteByte(0);                              // WordCount (no parameters)
        body.WriteUInt16((ushort)NtLm012Dialect.Length); // ByteCount
        body.WriteBytes(NtLm012Dialect);                // Dialects

        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteBytes(header.Pack());
        writer.WriteBytes(body.ToArray());
        return writer.ToArray();
    }
}
