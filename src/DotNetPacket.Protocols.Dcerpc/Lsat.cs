using System.Text;

namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>SID_NAME_USE (MS-LSAT 2.2.13): the kind of principal a SID resolves to.</summary>
public enum SidNameUse : ushort
{
    User = 1,
    Group = 2,
    Domain = 3,
    Alias = 4,
    WellKnownGroup = 5,
    DeletedAccount = 6,
    Invalid = 7,
    Unknown = 8,
    Computer = 9,
    Label = 10,
}

/// <summary>One resolved SID: its domain, account name, and principal kind.</summary>
public sealed record LsaResolvedSid(string InputSid, string Domain, string Name, SidNameUse Use)
{
    public string Display => string.IsNullOrEmpty(Domain) ? Name : $@"{Domain}\{Name}";
}

/// <summary>One resolved name: the input name, its full SID, and principal kind.</summary>
public sealed record LsaResolvedName(string InputName, string Sid, SidNameUse Use);

/// <summary>
/// Minimal lsat client (MS-LSAT). Port of the SID→name lookup in impacket's
/// <c>dcerpc.v5.lsat</c> — the <c>lookupsid</c> recon behavior. Shares the lsarpc
/// pipe/interface; the pipe must be bound and a policy handle opened first
/// (see <see cref="Lsarpc"/>). Byte layout verified against impacket.
/// </summary>
public static class Lsat
{
    private const ushort OpnumLsarLookupNames = 14;
    private const ushort OpnumLsarLookupSids = 15;
    private const ushort LsapLookupWksta = 1; // LSAP_LOOKUP_LEVEL

    /// <summary>LsarLookupSids (opnum 15): translate SIDs to domain\name with a principal kind.</summary>
    public static IReadOnlyList<LsaResolvedSid> LookupSids(DcerpcPipe pipe, byte[] policyHandle, IReadOnlyList<string> sids)
    {
        byte[] stub = pipe.Call(OpnumLsarLookupSids, BuildRequest(policyHandle, sids));
        return ParseResponse(stub, sids);
    }

    private static byte[] BuildRequest(byte[] policyHandle, IReadOnlyList<string> sids)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(policyHandle);

        // LSAPR_SID_ENUM_BUFFER { ULONG Entries; [size_is] PLSAPR_SID_INFORMATION SidInfo; }
        ndr.WriteUInt32((uint)sids.Count);        // Entries
        ndr.WriteReferent(true);                  // SidInfo pointer
        ndr.WriteUInt32((uint)sids.Count);        // conformant MaxCount
        foreach (string _ in sids)
        {
            ndr.WriteReferent(true);              // each LSAPR_SID_INFORMATION.Sid pointer
        }

        foreach (string sid in sids)
        {
            (byte revision, byte[] authority, uint[] subs) = ParseSid(sid);
            ndr.WriteSid(revision, authority, subs);
        }

        // LSAPR_TRANSLATED_NAMES (empty on input).
        ndr.WriteUInt32(0);                       // Entries
        ndr.WriteReferent(false);                 // Names (NULL)

        ndr.WriteUInt16(LsapLookupWksta);         // LookupLevel (enum16)
        ndr.WriteUInt32(0);                       // MappedCount
        return ndr.ToArray();
    }

    /// <summary>Parses an LsarLookupSids response stub (exposed for tests / offline analysis).</summary>
    public static IReadOnlyList<LsaResolvedSid> ParseResponse(byte[] stub, IReadOnlyList<string> sids)
    {
        var reader = new NdrReader(stub);

        // --- ReferencedDomains: LSAPR_REFERENCED_DOMAIN_LIST ---
        var domains = new List<string>();
        reader.ReadReferent();                    // ReferencedDomains pointer
        uint domainEntries = reader.ReadUInt32();
        uint domainsRef = reader.ReadReferent();
        reader.ReadUInt32();                      // MaxEntries

        var domainNameRefs = new uint[domainEntries];
        var domainSidRefs = new uint[domainEntries];
        if (domainsRef != 0)
        {
            reader.ReadUInt32();                  // array MaxCount
            for (int i = 0; i < domainEntries; i++)
            {
                reader.ReadUInt16();              // Name.Length
                reader.ReadUInt16();              // Name.MaximumLength
                domainNameRefs[i] = reader.ReadReferent();
                domainSidRefs[i] = reader.ReadReferent();
            }

            for (int i = 0; i < domainEntries; i++)
            {
                domains.Add(domainNameRefs[i] != 0 ? ReadConformantVaryingString(reader) : string.Empty);
                if (domainSidRefs[i] != 0)
                {
                    ReadSid(reader); // domain SID (not needed for display, but must be consumed)
                }
            }
        }

        // --- TranslatedNames: LSAPR_TRANSLATED_NAMES ---
        uint nameEntries = reader.ReadUInt32();
        uint namesRef = reader.ReadReferent();

        var uses = new SidNameUse[nameEntries];
        var domainIndexes = new int[nameEntries];
        var nameRefs = new uint[nameEntries];
        if (namesRef != 0)
        {
            reader.ReadUInt32();                  // array MaxCount
            for (int i = 0; i < nameEntries; i++)
            {
                uses[i] = (SidNameUse)reader.ReadUInt16();
                reader.Align(4);                  // enum16 + pad before the RPC_UNICODE_STRING
                reader.ReadUInt16();              // Name.Length
                reader.ReadUInt16();              // Name.MaximumLength
                nameRefs[i] = reader.ReadReferent();
                domainIndexes[i] = (int)reader.ReadUInt32();
            }
        }

        var names = new string[nameEntries];
        for (int i = 0; i < nameEntries; i++)
        {
            names[i] = nameRefs[i] != 0 ? ReadConformantVaryingString(reader) : string.Empty;
        }

        var results = new List<LsaResolvedSid>();
        for (int i = 0; i < nameEntries; i++)
        {
            int di = domainIndexes[i];
            string domain = di >= 0 && di < domains.Count ? domains[di] : string.Empty;
            string inputSid = i < sids.Count ? sids[i] : string.Empty;
            results.Add(new LsaResolvedSid(inputSid, domain, names[i], uses[i]));
        }

        return results;
    }

    /// <summary>LsarLookupNames (opnum 14): translate account names to SIDs (name -> SID).</summary>
    public static IReadOnlyList<LsaResolvedName> LookupNames(DcerpcPipe pipe, byte[] policyHandle, IReadOnlyList<string> names)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(policyHandle);
        ndr.WriteUInt32((uint)names.Count);       // Count
        ndr.WriteUInt32((uint)names.Count);       // Names array MaxCount
        foreach (string name in names)
        {
            ndr.WriteUnicodeStringHeader(name);
        }

        foreach (string name in names)
        {
            ndr.WriteUnicodeStringBuffer(name);
        }

        ndr.WriteUInt32(0);                       // TranslatedSids.Entries
        ndr.WriteReferent(false);                 // TranslatedSids.Sids (NULL)
        ndr.WriteUInt16(LsapLookupWksta);         // LookupLevel
        ndr.WriteUInt32(0);                       // MappedCount

        byte[] stub = pipe.Call(OpnumLsarLookupNames, ndr.ToArray());
        return ParseLookupNames(stub, names);
    }

    /// <summary>Parses an LsarLookupNames response (referenced domains + translated SIDs). Exposed for tests.</summary>
    public static IReadOnlyList<LsaResolvedName> ParseLookupNames(byte[] stub, IReadOnlyList<string> names)
    {
        var reader = new NdrReader(stub);

        reader.ReadReferent();                    // ReferencedDomains pointer
        uint domainEntries = reader.ReadUInt32();
        uint domainsRef = reader.ReadReferent();
        reader.ReadUInt32();                      // MaxEntries

        var domainNameRefs = new uint[domainEntries];
        var domainSidRefs = new uint[domainEntries];
        if (domainsRef != 0)
        {
            reader.ReadUInt32();                  // array MaxCount
            for (int i = 0; i < domainEntries; i++)
            {
                reader.ReadUInt16();              // Name.Length
                reader.ReadUInt16();              // Name.MaximumLength
                domainNameRefs[i] = reader.ReadReferent();
                domainSidRefs[i] = reader.ReadReferent();
            }
        }

        var domainSids = new (byte Revision, byte[] Authority, uint[] Subs)?[domainEntries];
        for (int i = 0; i < domainEntries; i++)
        {
            if (domainNameRefs[i] != 0)
            {
                ReadConformantVaryingString(reader); // domain name (not needed for output)
            }

            domainSids[i] = domainSidRefs[i] != 0 ? ReadSidComponents(reader) : null;
        }

        uint sidEntries = reader.ReadUInt32();
        uint sidsRef = reader.ReadReferent();

        var uses = new SidNameUse[sidEntries];
        var rids = new uint[sidEntries];
        var domainIndexes = new int[sidEntries];
        if (sidsRef != 0)
        {
            reader.ReadUInt32();                  // array MaxCount
            for (int i = 0; i < sidEntries; i++)
            {
                uses[i] = (SidNameUse)reader.ReadUInt16();
                reader.Align(4);                  // enum16 + pad
                rids[i] = reader.ReadUInt32();
                domainIndexes[i] = (int)reader.ReadUInt32();
            }
        }

        var results = new List<LsaResolvedName>();
        for (int i = 0; i < sidEntries; i++)
        {
            string inputName = i < names.Count ? names[i] : string.Empty;
            string sid = string.Empty;
            int di = domainIndexes[i];
            if (di >= 0 && di < domainSids.Length && domainSids[di] is { } d)
            {
                var subs = new uint[d.Subs.Length + 1];
                Array.Copy(d.Subs, subs, d.Subs.Length);
                subs[^1] = rids[i];
                sid = Lsarpc.FormatSid(d.Revision, d.Authority, subs);
            }

            results.Add(new LsaResolvedName(inputName, sid, uses[i]));
        }

        return results;
    }

    private static (byte Revision, byte[] Authority, uint[] Subs) ReadSidComponents(NdrReader reader)
    {
        reader.ReadUInt32();                      // conformant MaxCount
        byte revision = reader.ReadByte();
        byte count = reader.ReadByte();
        byte[] authority = reader.ReadBytes(6);
        var subs = new uint[count];
        for (int i = 0; i < count; i++)
        {
            subs[i] = reader.ReadUInt32();
        }

        return (revision, authority, subs);
    }

    private static string ReadConformantVaryingString(NdrReader reader)
    {
        reader.ReadUInt32();                      // MaxCount
        reader.ReadUInt32();                      // Offset
        uint actual = reader.ReadUInt32();        // ActualCount
        return reader.ReadWideChars((int)actual).TrimEnd('\0');
    }

    private static void ReadSid(NdrReader reader)
    {
        reader.ReadUInt32();                      // conformant MaxCount
        reader.ReadByte();                        // Revision
        byte count = reader.ReadByte();           // SubAuthorityCount
        reader.ReadBytes(6);                      // IdentifierAuthority
        for (int i = 0; i < count; i++)
        {
            reader.ReadUInt32();                  // SubAuthority
        }
    }

    private static (byte Revision, byte[] Authority, uint[] SubAuthorities) ParseSid(string sid)
    {
        // "S-1-5-32-544" -> revision 1, authority 5, subs [32, 544]
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
