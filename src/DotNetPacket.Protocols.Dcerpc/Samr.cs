namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>A SAMPR_RID_ENUMERATION entry (MS-SAMR 2.2.7.10): a RID and its name.</summary>
public sealed record SamrRidEntry(uint Rid, string Name);

/// <summary>Result of a handle-returning samr call.</summary>
public sealed record SamrHandleResult(byte[] Handle, uint ReturnCode)
{
    public bool Success => ReturnCode == 0;
}

/// <summary>Result of an enumerate call: the entries plus the server's return status.</summary>
public sealed record SamrEnumResult(IReadOnlyList<SamrRidEntry> Entries, uint ReturnCode);

/// <summary>SAMPR_USER_GENERAL_INFORMATION (MS-SAMR 2.2.6.5): basic account attributes.</summary>
public sealed record SamrUserGeneral(string UserName, string FullName, uint PrimaryGroupId, string AdminComment, string UserComment);

/// <summary>
/// SAMPR_USER_ALL_INFORMATION (MS-SAMR 2.2.6.6): the full per-user record returned by
/// SamrQueryInformationUser2 class 21 — the detail impacket's samrdump prints per account
/// (timestamps, account-control flags, bad-password / logon counters). Timestamps are raw
/// FILETIMEs (100ns ticks since 1601); use <see cref="Samr.FileTimeToUtc"/> to render them.
/// </summary>
public sealed record SamrUserAll(
    string UserName,
    string FullName,
    string AdminComment,
    uint UserId,
    uint PrimaryGroupId,
    uint UserAccountControl,
    uint WhichFields,
    ushort BadPasswordCount,
    ushort LogonCount,
    long LastLogon,
    long PasswordLastSet,
    long AccountExpires,
    long PasswordMustChange)
{
    /// <summary>Human-readable USER_ACCOUNT_* flag names set in <see cref="UserAccountControl"/>.</summary>
    public string AccountFlagsText => Samr.AccountFlagsText(UserAccountControl);
}

/// <summary>
/// DOMAIN_PASSWORD_INFORMATION (MS-SAMR 2.2.3.5): the domain password policy. Age
/// values are NT relative times (negative 100ns intervals); <see cref="RelativeTimeToDays"/>
/// converts them, returning null for "never expires".
/// </summary>
public sealed record SamrPasswordPolicy(
    ushort MinPasswordLength,
    ushort PasswordHistoryLength,
    uint PasswordProperties,
    long MaxPasswordAge,
    long MinPasswordAge);

/// <summary>DOMAIN_LOCKOUT_INFORMATION (MS-SAMR 2.2.3.14): the account-lockout policy.</summary>
public sealed record SamrLockoutPolicy(
    long LockoutDuration,
    long LockoutObservationWindow,
    ushort LockoutThreshold);

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
    private const ushort OpnumQueryInformationDomain = 8;
    private const ushort OpnumEnumerateGroups = 11;
    private const ushort OpnumEnumerateUsers = 13;
    private const ushort OpnumEnumerateAliases = 15;
    private const ushort OpnumOpenUser = 34;
    private const ushort OpnumQueryInformationUser2 = 47;

    private const uint MaximumAllowed = 0x02000000;
    private const uint UserNormalAccount = 0x00000010;
    private const ushort UserGeneralInformation = 1;
    private const ushort UserAllInformation = 21;
    private const ushort DomainPasswordInformation = 1;
    private const ushort DomainLockoutInformation = 12;

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

    /// <summary>SamrEnumerateGroupsInDomain (opnum 11): list domain groups (RID + name).</summary>
    public static SamrEnumResult EnumerateGroups(DcerpcPipe pipe, byte[] domainHandle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(domainHandle);
        ndr.WriteUInt32(0);                 // EnumerationContext
        ndr.WriteUInt32(0xFFFFFFFF);        // PreferedMaximumLength
        byte[] stub = pipe.Call(OpnumEnumerateGroups, ndr.ToArray());
        return ParseRidEnumeration(stub);
    }

    /// <summary>SamrEnumerateAliasesInDomain (opnum 15): list domain aliases/local groups (RID + name).</summary>
    public static SamrEnumResult EnumerateAliases(DcerpcPipe pipe, byte[] domainHandle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(domainHandle);
        ndr.WriteUInt32(0);                 // EnumerationContext
        ndr.WriteUInt32(0xFFFFFFFF);        // PreferedMaximumLength
        byte[] stub = pipe.Call(OpnumEnumerateAliases, ndr.ToArray());
        return ParseRidEnumeration(stub);
    }

    /// <summary>SamrOpenUser (opnum 34): open a user account by RID and get a user handle.</summary>
    public static SamrHandleResult OpenUser(DcerpcPipe pipe, byte[] domainHandle, uint rid, uint desiredAccess = MaximumAllowed)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(domainHandle);
        ndr.WriteUInt32(desiredAccess);
        ndr.WriteUInt32(rid);
        byte[] stub = pipe.Call(OpnumOpenUser, ndr.ToArray());

        var reader = new NdrReader(stub);
        byte[] handle = reader.ReadContextHandle();
        return new SamrHandleResult(handle, reader.ReadUInt32());
    }

    /// <summary>SamrQueryInformationUser2 (opnum 47), class UserGeneralInformation (level 1).</summary>
    public static SamrUserGeneral QueryUserGeneralInfo(DcerpcPipe pipe, byte[] userHandle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(userHandle);
        ndr.WriteUInt16(UserGeneralInformation);
        byte[] stub = pipe.Call(OpnumQueryInformationUser2, ndr.ToArray());
        return ParseUserGeneral(stub);
    }

    /// <summary>Parses a UserGeneralInformation response buffer (exposed for tests / offline analysis).</summary>
    public static SamrUserGeneral ParseUserGeneral(byte[] stub)
    {
        var reader = new NdrReader(stub);
        uint bufferReferent = reader.ReadReferent();
        if (bufferReferent == 0)
        {
            return new SamrUserGeneral(string.Empty, string.Empty, 0, string.Empty, string.Empty);
        }

        reader.ReadUInt32(); // union discriminant (level == 1)

        uint userNameRef = ReadUnicodeStringHeader(reader);
        uint fullNameRef = ReadUnicodeStringHeader(reader);
        uint primaryGroupId = reader.ReadUInt32();
        uint adminCommentRef = ReadUnicodeStringHeader(reader);
        uint userCommentRef = ReadUnicodeStringHeader(reader);

        string userName = userNameRef != 0 ? ReadConformantVaryingString(reader) : string.Empty;
        string fullName = fullNameRef != 0 ? ReadConformantVaryingString(reader) : string.Empty;
        string adminComment = adminCommentRef != 0 ? ReadConformantVaryingString(reader) : string.Empty;
        string userComment = userCommentRef != 0 ? ReadConformantVaryingString(reader) : string.Empty;

        return new SamrUserGeneral(userName, fullName, primaryGroupId, adminComment, userComment);
    }

    /// <summary>SamrQueryInformationUser2 (opnum 47), class UserAllInformation (level 21).</summary>
    public static SamrUserAll QueryUserAllInfo(DcerpcPipe pipe, byte[] userHandle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(userHandle);
        ndr.WriteUInt16(UserAllInformation);
        byte[] stub = pipe.Call(OpnumQueryInformationUser2, ndr.ToArray());
        return ParseUserAll(stub);
    }

    /// <summary>
    /// Parses a UserAllInformation (level 21) response buffer (exposed for tests / offline
    /// analysis). Reads the fixed SAMPR_USER_ALL_INFORMATION arm — six OLD_LARGE_INTEGER
    /// timestamps, ten RPC_UNICODE_STRING headers, two RPC_SHORT_BLOB headers, PrivateData,
    /// the security-descriptor pointer, the scalar ids/counters and LogonHours header — then
    /// walks the deferred string buffers in field order. The deferred password-blob /
    /// security-descriptor / logon-hours arrays are not decoded (the SAM returns the blobs
    /// NULL for this call); only the recon fields samrdump surfaces are extracted.
    /// </summary>
    public static SamrUserAll ParseUserAll(byte[] stub)
    {
        var reader = new NdrReader(stub);
        uint bufferReferent = reader.ReadReferent();
        if (bufferReferent == 0)
        {
            return new SamrUserAll(string.Empty, string.Empty, string.Empty, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }

        reader.ReadUInt32();                 // union discriminant (level == 21) + alignment pad

        long lastLogon = ReadFileTime(reader);
        reader.ReadInt64();                  // LastLogoff
        long passwordLastSet = ReadFileTime(reader);
        long accountExpires = ReadFileTime(reader);
        reader.ReadInt64();                  // PasswordCanChange
        long passwordMustChange = ReadFileTime(reader);

        uint userNameRef = ReadUnicodeStringHeader(reader);
        uint fullNameRef = ReadUnicodeStringHeader(reader);
        uint homeDirRef = ReadUnicodeStringHeader(reader);
        uint homeDriveRef = ReadUnicodeStringHeader(reader);
        uint scriptRef = ReadUnicodeStringHeader(reader);
        uint profileRef = ReadUnicodeStringHeader(reader);
        uint adminCommentRef = ReadUnicodeStringHeader(reader);
        uint workstationsRef = ReadUnicodeStringHeader(reader);
        uint userCommentRef = ReadUnicodeStringHeader(reader);
        uint parametersRef = ReadUnicodeStringHeader(reader);

        ReadUnicodeStringHeader(reader);     // LmOwfPassword RPC_SHORT_BLOB header (L/M/ref)
        ReadUnicodeStringHeader(reader);     // NtOwfPassword RPC_SHORT_BLOB header
        ReadUnicodeStringHeader(reader);     // PrivateData RPC_UNICODE_STRING header

        reader.ReadUInt32();                 // SecurityDescriptor.Length
        reader.ReadReferent();               // SecurityDescriptor pointer

        uint userId = reader.ReadUInt32();
        uint primaryGroupId = reader.ReadUInt32();
        uint userAccountControl = reader.ReadUInt32();
        uint whichFields = reader.ReadUInt32();

        reader.ReadUInt32();                 // LogonHours.UnitsPerWeek
        reader.ReadReferent();               // LogonHours pointer

        ushort badPasswordCount = reader.ReadUInt16();
        ushort logonCount = reader.ReadUInt16();
        reader.ReadUInt16();                 // CountryCode
        reader.ReadUInt16();                 // CodePage
        reader.ReadByte();                   // LmPasswordPresent
        reader.ReadByte();                   // NtPasswordPresent
        reader.ReadByte();                   // PasswordExpired
        reader.ReadByte();                   // PrivateDataSensitive

        // Deferred buffers, in pointer (field) order. Only the strings are present here.
        string userName = userNameRef != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        string fullName = fullNameRef != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        if (homeDirRef != 0) reader.ReadConformantVaryingString();
        if (homeDriveRef != 0) reader.ReadConformantVaryingString();
        if (scriptRef != 0) reader.ReadConformantVaryingString();
        if (profileRef != 0) reader.ReadConformantVaryingString();
        string adminComment = adminCommentRef != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        if (workstationsRef != 0) reader.ReadConformantVaryingString();
        if (userCommentRef != 0) reader.ReadConformantVaryingString();
        if (parametersRef != 0) reader.ReadConformantVaryingString();

        return new SamrUserAll(
            userName, fullName, adminComment,
            userId, primaryGroupId, userAccountControl, whichFields,
            badPasswordCount, logonCount,
            lastLogon, passwordLastSet, accountExpires, passwordMustChange);
    }

    /// <summary>Reads an OLD_LARGE_INTEGER (LowPart u32, HighPart i32) as a 64-bit FILETIME.</summary>
    private static long ReadFileTime(NdrReader reader)
    {
        uint low = reader.ReadUInt32();
        uint high = reader.ReadUInt32();
        return ((long)high << 32) | low;
    }

    /// <summary>
    /// Converts a SAM FILETIME (100ns ticks since 1601) to UTC, returning null for the
    /// 0 ("not set") and 0x7FFFFFFFFFFFFFFF ("never") sentinels.
    /// </summary>
    public static DateTime? FileTimeToUtc(long fileTime)
    {
        if (fileTime == 0 || fileTime == long.MaxValue)
        {
            return null;
        }

        try
        {
            return DateTime.FromFileTimeUtc(fileTime);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static readonly (uint Bit, string Name)[] UserAccountFlags =
    {
        (0x00000001, "DISABLED"),
        (0x00000004, "PASSWD_NOTREQD"),
        (0x00000010, "NORMAL_ACCOUNT"),
        (0x00000040, "INTERDOMAIN_TRUST"),
        (0x00000080, "WORKSTATION_TRUST"),
        (0x00000100, "SERVER_TRUST"),
        (0x00000200, "DONT_EXPIRE_PASSWD"),
        (0x00000400, "AUTO_LOCKED"),
        (0x00001000, "SMARTCARD_REQUIRED"),
        (0x00002000, "TRUSTED_FOR_DELEGATION"),
        (0x00004000, "NOT_DELEGATED"),
        (0x00008000, "USE_DES_KEY_ONLY"),
        (0x00010000, "DONT_REQUIRE_PREAUTH"),
        (0x00020000, "PASSWORD_EXPIRED"),
        (0x00040000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
    };

    /// <summary>Renders the USER_ACCOUNT_* (MS-SAMR 2.2.1.13) flag names set in a UserAccountControl value.</summary>
    public static string AccountFlagsText(uint uac)
    {
        var set = UserAccountFlags.Where(f => (uac & f.Bit) != 0).Select(f => f.Name).ToArray();
        return set.Length == 0 ? "(none)" : string.Join(" | ", set);
    }

    /// <summary>SamrQueryInformationDomain (opnum 8), class DomainPasswordInformation (level 1).</summary>
    public static SamrPasswordPolicy QueryPasswordPolicy(DcerpcPipe pipe, byte[] domainHandle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(domainHandle);
        ndr.WriteUInt16(DomainPasswordInformation);
        return ParsePasswordPolicy(pipe.Call(OpnumQueryInformationDomain, ndr.ToArray()));
    }

    /// <summary>SamrQueryInformationDomain (opnum 8), class DomainLockoutInformation (level 12).</summary>
    public static SamrLockoutPolicy QueryLockoutPolicy(DcerpcPipe pipe, byte[] domainHandle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(domainHandle);
        ndr.WriteUInt16(DomainLockoutInformation);
        return ParseLockoutPolicy(pipe.Call(OpnumQueryInformationDomain, ndr.ToArray()));
    }

    /// <summary>Parses a DomainPasswordInformation response buffer (referent + union tag + struct).</summary>
    public static SamrPasswordPolicy ParsePasswordPolicy(byte[] stub)
    {
        var reader = new NdrReader(stub);
        reader.ReadReferent();          // Buffer pointer
        reader.ReadUInt32();            // union discriminant (== level 1)

        ushort minLength = reader.ReadUInt16();
        ushort history = reader.ReadUInt16();
        uint properties = reader.ReadUInt32();
        long maxAge = reader.ReadInt64();
        long minAge = reader.ReadInt64();
        return new SamrPasswordPolicy(minLength, history, properties, maxAge, minAge);
    }

    /// <summary>Parses a DomainLockoutInformation response buffer (referent + union tag + struct).</summary>
    public static SamrLockoutPolicy ParseLockoutPolicy(byte[] stub)
    {
        var reader = new NdrReader(stub);
        reader.ReadReferent();          // Buffer pointer
        reader.ReadUInt32();            // union discriminant (== level 12)

        long duration = reader.ReadInt64();
        long window = reader.ReadInt64();
        ushort threshold = reader.ReadUInt16();
        return new SamrLockoutPolicy(duration, window, threshold);
    }

    /// <summary>
    /// Converts an NT relative-time value (negative 100ns intervals, as used by the SAM
    /// age/duration fields) to whole days, or null for the "never" sentinel.
    /// </summary>
    public static double? RelativeTimeToDays(long relativeTime)
    {
        if (relativeTime == 0 || relativeTime == long.MinValue)
        {
            return null; // 0 or 0x8000000000000000 => no limit / never
        }

        return -relativeTime / 1e7 / 86400.0;
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

    private static uint ReadUnicodeStringHeader(NdrReader reader)
    {
        reader.ReadUInt16();         // Length
        reader.ReadUInt16();         // MaximumLength
        return reader.ReadReferent(); // Buffer pointer
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
