namespace NetPacket.Protocols.Dcerpc;

/// <summary>A SAMPR_RID_ENUMERATION entry (MS-SAMR 2.2.7.10): a RID and its name.</summary>
public sealed record SamrRidEntry(uint Rid, string Name);

/// <summary>Result of a handle-returning samr call.</summary>
public sealed record SamrHandleResult(byte[] Handle, uint ReturnCode)
{
    public bool Success => ReturnCode == 0;
}

/// <summary>Result of an enumerate call: the entries plus the server's return status.</summary>
public sealed record SamrEnumResult(IReadOnlyList<SamrRidEntry> Entries, uint ReturnCode);

/// <summary>A parsed RPC_SID in component form (so it can be re-marshalled and displayed).</summary>
public sealed record SamrSid(byte Revision, byte[] IdentifierAuthority, uint[] SubAuthorities)
{
    public override string ToString() => Lsarpc.FormatSid(Revision, IdentifierAuthority, SubAuthorities);
}

/// <summary>
/// Minimal samr client (MS-SAMR). Port of the SAM enumeration path in impacket's
/// <c>dcerpc.v5.samr</c> — the samrdump / enumdomusers recon behavior: connect,
/// enumerate domains, resolve a domain SID, open it, enumerate its users. The pipe
/// must already be bound to the samr interface. Byte layout verified against impacket.
/// </summary>
public static class Samr
{
    private const ushort OpnumConnect = 0;
    private const ushort OpnumCloseHandle = 1;
    private const ushort OpnumLookupDomain = 5;
    private const ushort OpnumEnumerateDomains = 6;
    private const ushort OpnumOpenDomain = 7;
    private const ushort OpnumEnumerateUsers = 13;

    private const uint MaximumAllowed = 0x02000000;
    private const uint UserNormalAccount = 0x00000010;

    /// <summary>SamrConnect (opnum 0): connect to the SAM server and get a server handle.</summary>
    public static SamrHandleResult Connect(DcerpcPipe pipe, uint desiredAccess = MaximumAllowed)
    {
        var ndr = new NdrWriter();
        ndr.WriteReferent(true); // ServerName (unique ptr to one WCHAR)
        ndr.WriteUInt16(0);      // the WCHAR (0)
        ndr.WriteUInt32(desiredAccess);
        byte[] stub = pipe.Call(OpnumConnect, ndr.ToArray());

        var reader = new NdrReader(stub);
        byte[] handle = reader.ReadContextHandle();
        return new SamrHandleResult(handle, reader.ReadUInt32());
    }

    /// <summary>SamrEnumerateDomainsInSamServer (opnum 6): list the SAM domains.</summary>
    public static SamrEnumResult EnumerateDomains(DcerpcPipe pipe, byte[] serverHandle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(serverHandle);
        ndr.WriteUInt32(0);          // EnumerationContext
        ndr.WriteUInt32(0xFFFFFFFF); // PreferedMaximumLength
        byte[] stub = pipe.Call(OpnumEnumerateDomains, ndr.ToArray());
        return ParseRidEnumeration(stub);
    }

    /// <summary>SamrLookupDomainInSamServer (opnum 5): resolve a domain name to its SID.</summary>
    public static (SamrSid? Sid, uint ReturnCode) LookupDomain(DcerpcPipe pipe, byte[] serverHandle, string domainName)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(serverHandle);
        ndr.WriteUnicodeStringHeader(domainName);
        ndr.WriteUnicodeStringBuffer(domainName);
        byte[] stub = pipe.Call(OpnumLookupDomain, ndr.ToArray());

        var reader = new NdrReader(stub);
        uint sidReferent = reader.ReadReferent();
        SamrSid? sid = sidReferent != 0 ? ReadSid(reader) : null;
        uint status = reader.ReadUInt32();
        return (sid, status);
    }

    /// <summary>SamrOpenDomain (opnum 7): open a domain by SID and get a domain handle.</summary>
    public static SamrHandleResult OpenDomain(DcerpcPipe pipe, byte[] serverHandle, SamrSid domainSid, uint desiredAccess = MaximumAllowed)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(serverHandle);
        ndr.WriteUInt32(desiredAccess);
        ndr.WriteSid(domainSid.Revision, domainSid.IdentifierAuthority, domainSid.SubAuthorities);
        byte[] stub = pipe.Call(OpnumOpenDomain, ndr.ToArray());

        var reader = new NdrReader(stub);
        byte[] handle = reader.ReadContextHandle();
        return new SamrHandleResult(handle, reader.ReadUInt32());
    }

    /// <summary>SamrEnumerateUsersInDomain (opnum 13): list user accounts (RID + name).</summary>
    public static SamrEnumResult EnumerateUsers(DcerpcPipe pipe, byte[] domainHandle, uint userAccountControl = UserNormalAccount)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(domainHandle);
        ndr.WriteUInt32(0);                 // EnumerationContext
        ndr.WriteUInt32(userAccountControl);
        ndr.WriteUInt32(0xFFFFFFFF);        // PreferedMaximumLength
        byte[] stub = pipe.Call(OpnumEnumerateUsers, ndr.ToArray());
        return ParseRidEnumeration(stub);
    }

    /// <summary>SamrCloseHandle (opnum 1): release a server/domain handle.</summary>
    public static uint CloseHandle(DcerpcPipe pipe, byte[] handle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(handle);
        byte[] stub = pipe.Call(OpnumCloseHandle, ndr.ToArray());

        var reader = new NdrReader(stub);
        reader.ReadContextHandle();
        return reader.ReadUInt32();
    }

    /// <summary>
    /// Parses a SAMPR_ENUM_INFORMATION_BUFFER response (shared by EnumerateDomains /
    /// EnumerateUsers): EnumerationContext, a pointer to a count + RID-enumeration array,
    /// and CountReturned. Exposed for tests / offline analysis.
    /// </summary>
    public static SamrEnumResult ParseRidEnumeration(byte[] stub)
    {
        var reader = new NdrReader(stub);

        reader.ReadUInt32();                 // EnumerationContext (out)
        uint bufferReferent = reader.ReadReferent();

        var entries = new List<SamrRidEntry>();
        if (bufferReferent != 0)
        {
            uint entriesRead = reader.ReadUInt32();
            uint arrayReferent = reader.ReadReferent();
            if (arrayReferent != 0)
            {
                reader.ReadUInt32();         // array MaxCount
                var rids = new uint[entriesRead];
                var nameRefs = new uint[entriesRead];
                for (int i = 0; i < entriesRead; i++)
                {
                    rids[i] = reader.ReadUInt32();
                    reader.ReadUInt16();     // Name.Length
                    reader.ReadUInt16();     // Name.MaximumLength
                    nameRefs[i] = reader.ReadReferent();
                }

                for (int i = 0; i < entriesRead; i++)
                {
                    string name = nameRefs[i] != 0 ? ReadConformantVaryingString(reader) : string.Empty;
                    entries.Add(new SamrRidEntry(rids[i], name));
                }
            }
        }

        reader.ReadUInt32();                 // CountReturned
        uint status = reader.ReadUInt32();
        return new SamrEnumResult(entries, status);
    }

    private static string ReadConformantVaryingString(NdrReader reader)
    {
        reader.ReadUInt32();                 // MaxCount
        reader.ReadUInt32();                 // Offset
        uint actual = reader.ReadUInt32();   // ActualCount
        return reader.ReadWideChars((int)actual).TrimEnd('\0');
    }

    private static SamrSid ReadSid(NdrReader reader)
    {
        reader.ReadUInt32();                 // conformant MaxCount
        byte revision = reader.ReadByte();
        byte count = reader.ReadByte();
        byte[] authority = reader.ReadBytes(6);
        var subs = new uint[count];
        for (int i = 0; i < count; i++)
        {
            subs[i] = reader.ReadUInt32();
        }

        return new SamrSid(revision, authority, subs);
    }
}
