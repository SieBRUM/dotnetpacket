namespace NetPacket.Protocols.Ntlm;

/// <summary>Shared NTLMSSP constants (MS-NLMP). Port of values in impacket's <c>ntlm</c> module.</summary>
public static class Ntlm
{
    /// <summary>The NTLMSSP message signature: <c>"NTLMSSP\0"</c>.</summary>
    public static readonly byte[] Signature = { 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00 };

    public const uint NegotiateMessage = 1;
    public const uint ChallengeMessage = 2;
    public const uint AuthenticateMessage = 3;
}
