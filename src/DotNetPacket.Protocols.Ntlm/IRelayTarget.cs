namespace DotNetPacket.Protocols.Ntlm;

/// <summary>
/// The target side of an NTLM relay (ntlmrelayx): something that forwards a victim's NTLM tokens to
/// the real target server and returns the target's responses. The relay servers (SMB, HTTP, …) are
/// protocol-specific on the <em>inbound</em> victim side but share this outbound target bridge;
/// implemented for SMB by <c>Smb2RelayClientTarget</c>.
/// </summary>
public interface IRelayTarget
{
    /// <summary>Send the victim's NTLM NEGOTIATE (Type 1) to the target; return the target's CHALLENGE (Type 2).</summary>
    byte[] Negotiate(byte[] victimType1);

    /// <summary>Send the victim's NTLM AUTHENTICATE (Type 3) (+ optional MIC) to the target; return its NT status.</summary>
    uint Authenticate(byte[] victimType3, byte[]? mechListMic);
}
