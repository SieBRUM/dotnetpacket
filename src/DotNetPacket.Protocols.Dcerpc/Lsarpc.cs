using System.Text;

namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>Result of the account-domain policy query: the domain name and SID.</summary>
public sealed record LsaAccountDomain(string Name, string Sid, uint Status)
{
    public bool Success => Status == 0;
}

/// <summary>An LSA privilege definition (MS-LSAD LSAPR_POLICY_PRIVILEGE_DEF): name + LUID.</summary>
public sealed record LsaPrivilege(string Name, uint LuidLow, int LuidHigh);

/// <summary>
/// The system-access rights and privileges the LSA has assigned to one account SID
/// (MS-LSAD LsarEnumerateAccountRights). <see cref="Rights"/> holds the right names
/// (e.g. <c>SeBackupPrivilege</c>, <c>SeInteractiveLogonRight</c>).
/// </summary>
public sealed record LsaAccountRights(string Sid, IReadOnlyList<string> Rights, uint Status)
{
    public bool Success => Status == 0;

    /// <summary>STATUS_OBJECT_NAME_NOT_FOUND — the SID has no LSA account object (no rights assigned).</summary>
    public bool NotFound => Status == 0xC0000034;
}

/// <summary>
/// LSAPR_POLICY_DNS_DOMAIN_INFO (MS-LSAD 2.2.4.4): the DNS/forest identity of a domain
/// — NetBIOS name, DNS domain, DNS forest, domain GUID, and domain SID.
/// </summary>
public sealed record LsaDnsDomain(
    string NetbiosName,
    string DnsDomainName,
    string DnsForestName,
    string DomainGuid,
    string Sid,
    uint Status)
{
    public bool Success => Status == 0;
}

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
    private const ushort OpnumLsarLookupPrivilegeValue = 31;
    private const ushort OpnumLsarLookupPrivilegeName = 32;
    private const ushort OpnumLsarEnumerateAccountRights = 36;
    private const ushort OpnumLsarOpenPolicy2 = 44;
    private const ushort OpnumLsarQueryInformationPolicy2 = 46;

    private const uint MaximumAllowed = 0x02000000;
    private const ushort PolicyAccountDomainInformation = 5;
    private const ushort PolicyDnsDomainInformation = 12;

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

    /// <summary>
    /// LsarLookupPrivilegeValue (opnum 31): resolve a privilege name (e.g.
    /// <c>SeDebugPrivilege</c>) to its local LUID. Port of impacket's
    /// <c>hLsarLookupPrivilegeValue</c>. The Name goes out as an RPC_UNICODE_STRING
    /// (exact-count buffer, no NUL — same marshalling as the lsat name lookups).
    /// </summary>
    public static (uint LuidLow, int LuidHigh, uint Status) LookupPrivilegeValue(DcerpcPipe pipe, byte[] policyHandle, string name)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(policyHandle);   // PolicyHandle [in]
        ndr.WriteUnicodeStringHeader(name);      // Name header (Length/MaxLength + buffer referent)
        ndr.WriteUnicodeStringBuffer(name);      // Name buffer (conformant-varying, no NUL)
        return ParsePrivilegeValue(pipe.Call(OpnumLsarLookupPrivilegeValue, ndr.ToArray()));
    }

    /// <summary>Parses an LsarLookupPrivilegeValue response: a LUID (LowPart, HighPart) + NTSTATUS.</summary>
    public static (uint LuidLow, int LuidHigh, uint Status) ParsePrivilegeValue(byte[] stub)
    {
        var reader = new NdrReader(stub);
        uint low = reader.ReadUInt32();     // Value.LowPart
        int high = (int)reader.ReadUInt32(); // Value.HighPart
        uint status = reader.ReadUInt32();  // ErrorCode
        return (low, high, status);
    }

    /// <summary>
    /// LsarLookupPrivilegeName (opnum 32): resolve a privilege LUID back to its name — the
    /// reverse of <see cref="LookupPrivilegeValue"/>. Port of impacket's
    /// <c>hLsarLookupPrivilegeName</c>. The response Name is a referenced RPC_UNICODE_STRING.
    /// </summary>
    public static (string Name, uint Status) LookupPrivilegeName(DcerpcPipe pipe, byte[] policyHandle, uint luidLow, int luidHigh)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(policyHandle); // PolicyHandle [in]
        ndr.WriteUInt32(luidLow);             // Value.LowPart
        ndr.WriteUInt32((uint)luidHigh);      // Value.HighPart
        return ParsePrivilegeName(pipe.Call(OpnumLsarLookupPrivilegeName, ndr.ToArray()));
    }

    /// <summary>Parses an LsarLookupPrivilegeName response: a referenced RPC_UNICODE_STRING name + NTSTATUS.</summary>
    public static (string Name, uint Status) ParsePrivilegeName(byte[] stub)
    {
        var reader = new NdrReader(stub);
        if (reader.ReadReferent() == 0)        // Name pointer
        {
            return (string.Empty, reader.ReadUInt32());
        }

        reader.ReadUInt16();                   // Name.Length (bytes)
        reader.ReadUInt16();                   // Name.MaximumLength
        uint bufRef = reader.ReadReferent();   // Name.Buffer pointer
        string name = bufRef != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        uint status = reader.ReadUInt32();     // ErrorCode
        return (name, status);
    }

    /// <summary>
    /// LsarEnumerateAccountRights (opnum 36): list the system-access rights and privileges
    /// the LSA has granted to one account SID. Port of impacket's
    /// <c>hLsarEnumerateAccountRights</c>. The request is just the policy handle plus the
    /// account SID embedded as a conformant RPC_SID (no referent) — there are no
    /// discretionary request fields, so nothing here fingerprints the runtime.
    /// </summary>
    public static LsaAccountRights EnumerateAccountRights(DcerpcPipe pipe, byte[] policyHandle, string sid)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(policyHandle);              // PolicyHandle [in]
        (byte revision, byte[] authority, uint[] subs) = ParseSid(sid);
        ndr.WriteSid(revision, authority, subs);           // AccountSid [in] (embedded RPC_SID)
        return ParseAccountRights(pipe.Call(OpnumLsarEnumerateAccountRights, ndr.ToArray()), sid);
    }

    /// <summary>
    /// Parses an LsarEnumerateAccountRights response: an LSAPR_USER_RIGHT_SET
    /// (EntriesRead + a referent to a conformant RPC_UNICODE_STRING array — Length/
    /// MaxLength/Buffer-referent headers, then deferred conformant-varying name buffers),
    /// then the NTSTATUS. Exposed for tests / offline analysis.
    /// </summary>
    public static LsaAccountRights ParseAccountRights(byte[] stub, string sid)
    {
        var reader = new NdrReader(stub);
        uint entries = reader.ReadUInt32();   // EntriesRead
        if (reader.ReadReferent() == 0)       // UserRights array pointer
        {
            return new LsaAccountRights(sid, Array.Empty<string>(), reader.ReadUInt32());
        }

        reader.ReadUInt32();                  // conformant max_count

        // Inline RPC_UNICODE_STRING headers first: {Length, MaxLength, Buffer referent}.
        var bufRefs = new uint[entries];
        for (uint i = 0; i < entries; i++)
        {
            reader.ReadUInt16();              // Length (bytes)
            reader.ReadUInt16();              // MaximumLength
            bufRefs[i] = reader.ReadReferent(); // Buffer pointer
        }

        // Then the deferred conformant-varying name buffers, in order.
        var rights = new List<string>((int)entries);
        for (uint i = 0; i < entries; i++)
        {
            rights.Add(bufRefs[i] != 0 ? reader.ReadConformantVaryingString() : string.Empty);
        }

        uint status = reader.ReadUInt32();    // ErrorCode (NTSTATUS)
        return new LsaAccountRights(sid, rights, status);
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

    /// <summary>
    /// LsarQueryInformationPolicy2 (opnum 46), class PolicyDnsDomainInformation — the
    /// DNS/forest identity of the domain. Only meaningful on a domain controller.
    /// </summary>
    public static LsaDnsDomain QueryDnsDomain(DcerpcPipe pipe, byte[] policyHandle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(policyHandle);            // PolicyHandle [in]
        ndr.WriteUInt16(PolicyDnsDomainInformation);     // InformationClass (enum16)
        byte[] stub = pipe.Call(OpnumLsarQueryInformationPolicy2, ndr.ToArray());
        return ParseDnsDomain(stub);
    }

    /// <summary>
    /// Parses a PolicyDnsDomainInformation response (union referent + tag 12, three
    /// RPC_UNICODE_STRING headers, a 16-byte DomainGuid, and an RPC_SID pointer, then the
    /// deferred string buffers and SID). Exposed for tests / offline analysis.
    /// </summary>
    public static LsaDnsDomain ParseDnsDomain(byte[] stub)
    {
        var reader = new NdrReader(stub);
        if (reader.ReadReferent() == 0)
        {
            return new LsaDnsDomain(string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, reader.ReadUInt32());
        }

        reader.ReadUInt32(); // union discriminant (ULONG tag == 12)

        uint nameRef = ReadUnicodeStringHeader(reader);
        uint dnsRef = ReadUnicodeStringHeader(reader);
        uint forestRef = ReadUnicodeStringHeader(reader);
        var guid = new Guid(reader.ReadBytes(16));
        uint sidRef = reader.ReadReferent();

        string netbios = nameRef != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        string dns = dnsRef != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        string forest = forestRef != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        string sid = sidRef != 0 ? ReadSid(reader) : string.Empty;

        uint status = reader.ReadUInt32();
        return new LsaDnsDomain(netbios, dns, forest, guid.ToString(), sid, status);
    }

    private static uint ReadUnicodeStringHeader(NdrReader reader)
    {
        reader.ReadUInt16(); // Length (bytes)
        reader.ReadUInt16(); // MaximumLength (bytes)
        return reader.ReadReferent();
    }

    private static string ReadSid(NdrReader reader)
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

        return FormatSid(revision, identifierAuthority, subAuthorities);
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

    /// <summary>Parses a canonical S-R-IA-SA... SID into (revision, 6-byte authority, sub-authorities).</summary>
    private static (byte Revision, byte[] Authority, uint[] SubAuthorities) ParseSid(string sid)
    {
        string[] parts = sid.Split('-');
        byte revision = byte.Parse(parts[1]);
        ulong authority = ulong.Parse(parts[2]);
        var authorityBytes = new byte[6];
        for (int i = 5; i >= 0; i--)
        {
            authorityBytes[i] = (byte)(authority & 0xFF);
            authority >>= 8;
        }

        var subs = new uint[parts.Length - 3];
        for (int i = 0; i < subs.Length; i++)
        {
            subs[i] = uint.Parse(parts[i + 3]);
        }

        return (revision, authorityBytes, subs);
    }
}
