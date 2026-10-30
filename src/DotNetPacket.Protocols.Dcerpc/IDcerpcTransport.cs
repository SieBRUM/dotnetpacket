namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>
/// A DCERPC transport: carries whole PDUs to the server and back. The two bindings
/// DotNetPacket implements are <see cref="SmbPipeTransport"/> (ncacn_np — PDUs over an
/// SMB2 named pipe) and <see cref="TcpDcerpcTransport"/> (ncacn_ip_tcp — PDUs framed
/// directly on a TCP connection). <see cref="DcerpcPipe"/> drives the protocol
/// (bind, sign/seal, call) over whichever transport it is given.
/// </summary>
public interface IDcerpcTransport
{
    /// <summary>Sends one request PDU and returns the single response PDU.</summary>
    byte[] Transceive(byte[] pdu);

    /// <summary>Sends one PDU with no reply expected (used for AUTH3).</summary>
    void Send(byte[] pdu);

    /// <summary>Releases the transport (pipe handle or socket).</summary>
    void Close();
}
