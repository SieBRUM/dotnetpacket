namespace DotNetPacket.Protocols.Ntlm;

/// <summary>
/// NTLM "security buffer" (MS-NLMP 2.2.2.1): an 8-byte descriptor of a payload
/// field located elsewhere in the message. <see cref="Offset"/> is measured from
/// the start of the message.
/// </summary>
public struct SecurityBuffer
{
    /// <summary>Length in bytes of the payload this buffer points at.</summary>
    public ushort Length;

    /// <summary>Allocated length. DotNetPacket writes this equal to <see cref="Length"/>.</summary>
    public ushort MaxLength;

    /// <summary>Offset, from the start of the message, of the payload.</summary>
    public uint Offset;
}
