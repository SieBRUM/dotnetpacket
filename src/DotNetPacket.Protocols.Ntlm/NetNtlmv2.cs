namespace DotNetPacket.Protocols.Ntlm;

/// <summary>
/// Formats a captured NTLM AUTHENTICATE into the hashcat/john NetNTLM hash string — what ntlmrelayx
/// (and the impacket SMB server) print for every relayed/captured authentication so it can be cracked
/// offline. Port of <c>impacket.smbserver.outputToJohnFormat</c>.
/// </summary>
public static class NetNtlmv2
{
    /// <summary>
    /// Builds the hash line for a capture. For NTLMv2 (NT response &gt; 24 bytes) the format is
    /// <c>user::domain:serverChallenge:NTProofStr:blob</c> (hashcat mode 5600); for NTLMv1 it is
    /// <c>user::domain:LMresp:NTresp:serverChallenge</c> (mode 5500).
    /// </summary>
    public static string Format(byte[] serverChallenge, NtlmAuthenticate auth)
    {
        string chal = Hex(serverChallenge);
        if (auth.IsNtlmV2)
        {
            string nt = Hex(auth.NtChallengeResponse);
            string ntProof = nt[..32];   // first 16 bytes
            string blob = nt[32..];      // the NTLMv2 client-challenge blob
            return $"{auth.UserName}::{auth.DomainName}:{chal}:{ntProof}:{blob}";
        }

        return $"{auth.UserName}::{auth.DomainName}:{Hex(auth.LmChallengeResponse)}:{Hex(auth.NtChallengeResponse)}:{chal}";
    }

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
}
