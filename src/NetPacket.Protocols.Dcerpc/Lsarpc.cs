using System.Text;

namespace NetPacket.Protocols.Dcerpc;

/// <summary>Result of the account-domain policy query: the domain name and SID.</summary>
public sealed record LsaAccountDomain(string Name, string Sid, uint Status)
{
    public bool Success => Status == 0;
}

/// <summary>An LSA privilege definition (MS-LSAD LSAPR_POLICY_PRIVILEGE_DEF): name + LUID.</summary>
public sealed record LsaPrivilege(string Name, uint LuidLow, int LuidHigh);

/// <summary>
/// Minimal lsarpc client (MS-LSAD). Port of the parts of impacket's
/// <c>dcerpc.v5.lsad</c> used for domain recon: open the LSA policy and read the
/// account-domain name + SID (the precursor to SID lookups). The pipe must already
/// be bound to the lsarpc interface. Byte layout verified against impacket.
/// </summary>
public static class Lsarpc
{
    private const ushort OpnumLsarClose = 0;
    private const ushort OpnumLsarEnumeratePrivileges = 2;
    private const ushort OpnumLsarQueryInformationPolicy = 7;
    private const ushort OpnumLsarOpenPolicy2 = 44;

    private const uint MaximumAllowed = 0x02000000;
    private const ushort PolicyAccountDomainInformation = 5;

    /// <summary>LsarOpenPolicy2 (opnum 44): open a handle to the local LSA policy object.</summary>
    public static ScHandleResult OpenPolicy2(DcerpcPipe pipe, uint desiredAccess = MaximumAllowed)
    {
        var ndr = new NdrWriter();
        ndr.WriteUniqueString(null);        // SystemName [in,unique,string]
        // LSAPR_OBJECT_ATTRIBUTES: Length + 5 NULL/zero fields (24 bytes).
        ndr.WriteUInt32(0);                 // Length
        ndr.WriteReferent(false);           // RootDirectory
        ndr.WriteReferent(false);           // ObjectName
        ndr.WriteUInt32(0);                 // Attributes
        ndr.WriteReferent(false);           // SecurityDescriptor
        ndr.WriteReferent(false);           // SecurityQualityOfService
        ndr.WriteUInt32(desiredAccess);     // DesiredAccess
        byte[] stub = pipe.Call(OpnumLsarOpenPolicy2, ndr.ToArray());

        var reader = new NdrReader(stub);
        byte[] handle = reader.ReadContextHandle();
        uint status = reader.ReadUInt32();
        return new ScHandleResult(handle, status);
    }

    /// <summary>LsarQueryInformationPolicy (opnum 7), class PolicyAccountDomainInformation.</summary>
    public static LsaAccountDomain QueryAccountDomain(DcerpcPipe pipe, byte[] policyHandle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(policyHandle);          // PolicyHandle [in]
        ndr.WriteUInt16(PolicyAccountDomainInformation); // InformationClass (enum16)
        byte[] stub = pipe.Call(OpnumLsarQueryInformationPolicy, ndr.ToArray());
        return ParseAccountDomain(stub);
    }

    /// <summary>
    /// LsarEnumeratePrivileges (opnum 2): list the privileges the LSA knows about.
    /// Request is PolicyHandle + an in/out EnumerationContext + PreferedMaximumLength;
    /// a single call with a large maximum returns them all here. The enum4linux
    /// privilege-enumeration recon behavior.
    /// </summary>
    public static IReadOnlyList<LsaPrivilege> EnumeratePrivileges(DcerpcPipe pipe, byte[] policyHandle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(policyHandle); // PolicyHandle [in]
        ndr.WriteUInt32(0);                   // EnumerationContext [in,out] — start at 0
        ndr.WriteUInt32(0xFFFFFFFF);          // PreferedMaximumLength — "give me everything"
        return ParsePrivileges(pipe.Call(OpnumLsarEnumeratePrivileges, ndr.ToArray()));
    }

    /// <summary>
    /// Parses an LsarEnumeratePrivileges response: EnumerationContext, then an
    /// LSAPR_PRIVILEGE_ENUM_BUFFER (count + a conformant array of
    /// LSAPR_POLICY_PRIVILEGE_DEF, each an RPC_UNICODE_STRING name header + LUID, with
    /// the name buffers deferred). Exposed for tests / offline analysis.
    /// </summary>
    public static IReadOnlyList<LsaPrivilege> ParsePrivileges(byte[] stub)
    {
        var reader = new NdrReader(stub);
        reader.ReadUInt32();                  // EnumerationContext (out)
        uint entries = reader.ReadUInt32();   // Entries
        if (reader.ReadReferent() == 0)       // Privileges array pointer
        {
            return Array.Empty<LsaPrivilege>();
        }

        reader.ReadUInt32();                  // conformant max_count

        // Inline struct headers first: Name {Length, MaxLength, Buffer referent} + LUID.
        var lengths = new ushort[entries];
        var bufRefs = new uint[entries];
        var luidLow = new uint[entries];
        var luidHigh = new int[entries];
        for (uint i = 0; i < entries; i++)
        {
            lengths[i] = reader.ReadUInt16();         // Name.Length (bytes)
            reader.ReadUInt16();                      // Name.MaximumLength
            bufRefs[i] = reader.ReadReferent();       // Name.Buffer pointer
            luidLow[i] = reader.ReadUInt32();         // LUID.LowPart
            luidHigh[i] = (int)reader.ReadUInt32();   // LUID.HighPart
        }

        // Then the deferred conformant-varying name buffers, in order.
        var result = new List<LsaPrivilege>((int)entries);
        for (uint i = 0; i < entries; i++)
        {
            string name = bufRefs[i] != 0 ? reader.ReadConformantVaryingString() : string.Empty;
            result.Add(new LsaPrivilege(name, luidLow[i], luidHigh[i]));
        }

        return result;
    }

    /// <summary>LsarClose (opnum 0): release a policy handle.</summary>
    public static uint Close(DcerpcPipe pipe, byte[] handle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(handle);
        byte[] stub = pipe.Call(OpnumLsarClose, ndr.ToArray());

        var reader = new NdrReader(stub);
        reader.ReadContextHandle(); // echoed (nulled) handle
        return reader.ReadUInt32();
    }

    /// <summary>
    /// Parses a PolicyAccountDomainInformation response stub (LSAPR_POLICY_INFORMATION
    /// union -> LSAPR_POLICY_ACCOUNT_DOM_INFO). Exposed for tests / offline analysis.
    /// </summary>
    public static LsaAccountDomain ParseAccountDomain(byte[] stub)
    {
        var reader = new NdrReader(stub);

        uint unionReferent = reader.ReadReferent();
        if (unionReferent == 0)
        {
            return new LsaAccountDomain(string.Empty, string.Empty, reader.ReadUInt32());
        }

        reader.ReadUInt32(); // union discriminant (ULONG tag == 5)

        // DomainName RPC_UNICODE_STRING header.
        reader.ReadUInt16(); // Length (bytes)
        reader.ReadUInt16(); // MaximumLength (bytes)
        uint nameBufferReferent = reader.ReadReferent();

        uint sidReferent = reader.ReadReferent();

        string name = string.Empty;
        if (nameBufferReferent != 0)
        {
            reader.ReadUInt32();               // MaxCount
            reader.ReadUInt32();               // Offset
            uint actualCount = reader.ReadUInt32();
            name = reader.ReadWideChars((int)actualCount);
        }

        string sid = string.Empty;
        if (sidReferent != 0)
        {
            reader.ReadUInt32();               // conformant MaxCount (== SubAuthorityCount)
            byte revision = reader.ReadByte();
            byte subAuthorityCount = reader.ReadByte();
            byte[] identifierAuthority = reader.ReadBytes(6);
            var subAuthorities = new uint[subAuthorityCount];
            for (int i = 0; i < subAuthorityCount; i++)
            {
                subAuthorities[i] = reader.ReadUInt32();
            }

            sid = FormatSid(revision, identifierAuthority, subAuthorities);
        }

        uint status = reader.ReadUInt32();
        return new LsaAccountDomain(name, sid, status);
    }

    /// <summary>Formats an RPC_SID as the canonical S-R-IA-SA... string.</summary>
    public static string FormatSid(byte revision, byte[] identifierAuthority, uint[] subAuthorities)
    {
        ulong authority = 0;
        foreach (byte b in identifierAuthority)
        {
            authority = (authority << 8) | b;
        }

        var sb = new StringBuilder($"S-{revision}-{authority}");
        foreach (uint sub in subAuthorities)
        {
            sb.Append('-').Append(sub);
        }

        return sb.ToString();
    }
}
