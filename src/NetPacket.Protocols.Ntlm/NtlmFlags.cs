namespace NetPacket.Protocols.Ntlm;

/// <summary>NTLMSSP NEGOTIATE flags (MS-NLMP 2.2.2.5).</summary>
[Flags]
public enum NtlmNegotiateFlags : uint
{
    NegotiateUnicode = 0x00000001,
    NegotiateOem = 0x00000002,
    RequestTarget = 0x00000004,
    NegotiateSign = 0x00000010,
    NegotiateSeal = 0x00000020,
    NegotiateDatagram = 0x00000040,
    NegotiateLmKey = 0x00000080,
    NegotiateNtlm = 0x00000200,
    NegotiateAnonymous = 0x00000800,
    NegotiateOemDomainSupplied = 0x00001000,
    NegotiateOemWorkstationSupplied = 0x00002000,
    NegotiateAlwaysSign = 0x00008000,
    TargetTypeDomain = 0x00010000,
    TargetTypeServer = 0x00020000,
    NegotiateExtendedSessionSecurity = 0x00080000,
    NegotiateIdentify = 0x00100000,
    RequestNonNtSessionKey = 0x00400000,
    NegotiateTargetInfo = 0x00800000,
    NegotiateVersion = 0x02000000,
    Negotiate128 = 0x20000000,
    NegotiateKeyExchange = 0x40000000,
    Negotiate56 = 0x80000000,
}

/// <summary>AV_PAIR identifiers used in the NTLMv2 target-info list (MS-NLMP 2.2.2.1).</summary>
public enum NtlmAvId : ushort
{
    EOL = 0x0000,
    NbComputerName = 0x0001,
    NbDomainName = 0x0002,
    DnsComputerName = 0x0003,
    DnsDomainName = 0x0004,
    DnsTreeName = 0x0005,
    Flags = 0x0006,
    Timestamp = 0x0007,
    SingleHost = 0x0008,
    TargetName = 0x0009,
    ChannelBindings = 0x000A,
}
