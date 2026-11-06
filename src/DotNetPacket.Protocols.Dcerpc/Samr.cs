namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>A SAMPR_RID_ENUMERATION entry (MS-SAMR 2.2.7.10): a RID and its name.</summary>
public sealed record SamrRidEntry(uint Rid, string Name);

/// <summary>
/// A SamrLookupNamesInDomain result row: the requested name, its resolved RID, and the
/// SID_NAME_USE classification (MS-SAMR 2.2.1.9). Rid/Use are meaningful only when resolved.
/// </summary>
public sealed record SamrNameMapping(string Name, uint Rid, uint Use)
{
    public bool Resolved => Use != 0 && Use != 8 /* SidTypeUnknown */;

    /// <summary>Human-readable SID_NAME_USE name for <see cref="Use"/>.</summary>
    public string UseName => Use switch
    {
        1 => "User",
        2 => "Group",
        3 => "Domain",
        4 => "Alias",
        5 => "WellKnownGroup",
        6 => "DeletedAccount",
        7 => "Invalid",
        8 => "Unknown",
        9 => "Computer",
        10 => "Label",
        _ => $"Use({Use})",
    };
}

/// <summary>Result of a handle-returning samr call.</summary>
public sealed record SamrCreateUserResult(byte[] Handle, uint GrantedAccess, uint Rid, uint ReturnCode)
{
    public bool Succeeded => ReturnCode == 0;
}

public sealed record SamrHandleResult(byte[] Handle, uint ReturnCode)
{
    public bool Success => ReturnCode == 0;
}

/// <summary>Result of an enumerate call: the entries plus the server's return status.</summary>
public sealed record SamrEnumResult(IReadOnlyList<SamrRidEntry> Entries, uint ReturnCode);

/// <summary>SAMPR_USER_GENERAL_INFORMATION (MS-SAMR 2.2.6.5): basic account attributes.</summary>
public sealed record SamrUserGeneral(string UserName, string FullName, uint PrimaryGroupId, string AdminComment, string UserComment);

/// <summary>
/// One SAMPR_DOMAIN_DISPLAY_USER entry (MS-SAMR 2.2.8.6) — the record the display-information
/// enumeration (samrdump) returns per account: the 1-based display Index, the RID, the
/// USER_ACCOUNT_* control flags, and the account name / description / full name in a single
/// pass (no per-user OpenUser/QueryInformationUser round-trips).
/// </summary>
public sealed record SamrDisplayUser(
    uint Index,
    uint Rid,
    uint AccountControl,
    string AccountName,
    string AdminComment,
    string FullName)
{
    /// <summary>The USER_ACCOUNT_* flag names set in <see cref="AccountControl"/>.</summary>
    public string AccountControlText => Samr.AccountFlagsText(AccountControl);
}

/// <summary>
/// One SAMPR_DOMAIN_DISPLAY_GROUP entry (MS-SAMR 2.2.8.7) — the group record the display-group
/// enumeration returns: the 1-based display Index, the group RID, the SE_GROUP_* attribute flags,
/// and the group name + description.
/// </summary>
public sealed record SamrDisplayGroup(
    uint Index,
    uint Rid,
    uint Attributes,
    string AccountName,
    string AdminComment)
{
    /// <summary>The SE_GROUP_* attribute flag names set in <see cref="Attributes"/>.</summary>
    public string AttributesText => Samr.GroupAttributesText(Attributes);
}

/// <summary>
/// SAMPR_DOMAIN_GENERAL_INFORMATION (MS-SAMR 2.2.3.3) — the domain's general state: name, the
/// server's OEM description, replica source, server role/state, UAS-compat flag, and the live
/// user / group / alias object counts. The counts are the quick domain-size recon enum4linux /
/// samrdump print.
/// </summary>
public sealed record SamrDomainGeneral(
    string DomainName,
    string OemInformation,
    string ReplicaSourceNodeName,
    uint ServerState,
    uint ServerRole,
    bool UasCompatibilityRequired,
    uint UserCount,
    uint GroupCount,
    uint AliasCount,
    long ForceLogoff,
    long DomainModifiedCount,
    uint Status)
{
    public bool Success => Status == 0;

    /// <summary>DOMAIN_SERVER_ROLE (MS-SAMR 2.2.3.1): 2 = Backup (BDC), 3 = Primary (PDC).</summary>
    public string ServerRoleText => ServerRole switch
    {
        2 => "Backup",
        3 => "Primary",
        _ => $"({ServerRole})",
    };

    /// <summary>DOMAIN_SERVER_ENABLE_STATE (MS-SAMR 2.2.3.2): 1 = Enabled, 2 = Disabled.</summary>
    public string ServerStateText => ServerState switch
    {
        1 => "Enabled",
        2 => "Disabled",
        _ => $"({ServerState})",
    };
}

/// <summary>
/// A GROUP_MEMBERSHIP entry (MS-SAMR 2.2.7.2): one domain group the user belongs to — the
/// group RID and its SE_GROUP_* attribute flags. <see cref="GroupName"/> names the well-known
/// RIDs; <see cref="AttributesText"/> decodes the flag bits.
/// </summary>
public sealed record SamrGroupMembership(uint Rid, uint Attributes)
{
    /// <summary>Well-known group name for the RID, or "RID &lt;n&gt;" when not well-known.</summary>
    public string GroupName => Rid switch
    {
        512 => "Domain Admins",
        513 => "Domain Users",
        514 => "Domain Guests",
        515 => "Domain Computers",
        516 => "Domain Controllers",
        517 => "Cert Publishers",
        518 => "Schema Admins",
        519 => "Enterprise Admins",
        520 => "Group Policy Creator Owners",
        521 => "Read-only Domain Controllers",
        _ => $"RID {Rid}",
    };

    /// <summary>Human-readable SE_GROUP_* attribute names (MS-DTYP 2.4.3).</summary>
    public string AttributesText => Samr.GroupAttributesText(Attributes);
}

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
    private const ushort OpnumLookupNamesInDomain = 17;
    private const ushort OpnumLookupIdsInDomain = 18;
    private const ushort OpnumEnumerateDomains = 6;
    private const ushort OpnumOpenDomain = 7;
    private const ushort OpnumQueryInformationDomain = 8;
    private const ushort OpnumEnumerateGroups = 11;
    private const ushort OpnumEnumerateUsers = 13;
    private const ushort OpnumEnumerateAliases = 15;
    private const ushort OpnumOpenAlias = 27;
    private const ushort OpnumGetMembersInAlias = 33;
    private const ushort OpnumOpenUser = 34;
    private const ushort OpnumDeleteUser = 35;
    private const ushort OpnumCreateUser2InDomain = 50;
    private const ushort OpnumUnicodeChangePasswordUser2 = 55;

    /// <summary>ACCOUNT type for a machine/computer account (ACB_WSTRUST).</summary>
    public const uint UserWorkstationTrustAccount = 0x00000080;

    /// <summary>DOMAIN_CREATE_USER access right, needed on the domain handle to create an account.</summary>
    public const uint DomainCreateUser = 0x00000010;
    private const ushort OpnumGetGroupsForUser = 39;
    private const ushort OpnumQueryInformationUser2 = 47;
    private const ushort OpnumQueryDisplayInformation = 40;

    private const uint DomainDisplayUser = 1;      // DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser
    private const uint DomainDisplayGroup = 3;     // DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup
    private const uint StatusMoreEntries = 0x00000105; // STATUS_MORE_ENTRIES — server has more pages

    private const uint MaximumAllowed = 0x02000000;
    private const uint UserNormalAccount = 0x00000010;
    private const ushort UserGeneralInformation = 1;
    private const ushort UserAllInformation = 21;
    private const ushort DomainPasswordInformation = 1;
    private const ushort DomainGeneralInformation = 2;
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

    /// <summary>
    /// SamrLookupNamesInDomain (opnum 17): resolve account names to RIDs within a domain
    /// (name -> RID, the reverse of SamrLookupIdsInDomain). Port of impacket's
    /// <c>hSamrLookupNamesInDomain</c>. The Names parameter is a conformant-varying array of
    /// RPC_UNICODE_STRING with the IDL size_is(1000) upper bound; the element buffers are the
    /// exact-count (no-NUL) counted strings. Returns one row per requested name, in order.
    /// </summary>
    public static IReadOnlyList<SamrNameMapping> LookupNames(DcerpcPipe pipe, byte[] domainHandle, IReadOnlyList<string> names)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(domainHandle);
        ndr.WriteUInt32((uint)names.Count);   // Count
        ndr.WriteUInt32(1000);                 // Names array MaxCount (IDL size_is(1000))
        ndr.WriteUInt32(0);                    // Offset
        ndr.WriteUInt32((uint)names.Count);    // ActualCount (length_is(Count))
        foreach (string name in names)
        {
            ndr.WriteUnicodeStringHeader(name);
        }
        foreach (string name in names)
        {
            ndr.WriteUnicodeStringBuffer(name);
        }

        byte[] stub = pipe.Call(OpnumLookupNamesInDomain, ndr.ToArray());
        return ParseLookupNames(stub, names);
    }

    /// <summary>
    /// Parses a SamrLookupNamesInDomain response (two SAMPR_ULONG_ARRAYs — RelativeIds and Use —
    /// then the return code). Exposed for tests / offline analysis. On a partial-mapping status
    /// the arrays still line up with the requested names positionally.
    /// </summary>
    public static IReadOnlyList<SamrNameMapping> ParseLookupNames(byte[] stub, IReadOnlyList<string> names)
    {
        var reader = new NdrReader(stub);
        uint[] rids = ReadUlongArray(reader);
        uint[] uses = ReadUlongArray(reader);

        var result = new List<SamrNameMapping>(names.Count);
        for (int i = 0; i < names.Count; i++)
        {
            uint rid = i < rids.Length ? rids[i] : 0;
            uint use = i < uses.Length ? uses[i] : 0;
            result.Add(new SamrNameMapping(names[i], rid, use));
        }
        return result;
    }

    /// <summary>
    /// SamrLookupIdsInDomain (opnum 18): resolve RIDs to account names within a domain
    /// (RID -> name, the reverse of SamrLookupNamesInDomain). Port of impacket's
    /// <c>hSamrLookupIdsInDomain</c>. RelativeIds go out as a conformant-varying ULONG array
    /// with the IDL size_is(1000) bound; the response is a SAMPR_RETURNED_USTRING_ARRAY of names
    /// plus a SAMPR_ULONG_ARRAY of SID_NAME_USE. Returns one row per requested RID, in order.
    /// </summary>
    public static IReadOnlyList<SamrNameMapping> LookupIds(DcerpcPipe pipe, byte[] domainHandle, IReadOnlyList<uint> rids)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(domainHandle);
        ndr.WriteUInt32((uint)rids.Count);    // Count
        ndr.WriteUInt32(1000);                 // RelativeIds array MaxCount (IDL size_is(1000))
        ndr.WriteUInt32(0);                    // Offset
        ndr.WriteUInt32((uint)rids.Count);     // ActualCount (length_is(Count))
        foreach (uint rid in rids)
        {
            ndr.WriteUInt32(rid);
        }

        byte[] stub = pipe.Call(OpnumLookupIdsInDomain, ndr.ToArray());
        return ParseLookupIds(stub, rids);
    }

    /// <summary>
    /// Parses a SamrLookupIdsInDomain response (a SAMPR_RETURNED_USTRING_ARRAY of names, then a
    /// SAMPR_ULONG_ARRAY of SID_NAME_USE, then the return code). Exposed for tests / offline
    /// analysis. Names/uses line up positionally with the requested RIDs.
    /// </summary>
    public static IReadOnlyList<SamrNameMapping> ParseLookupIds(byte[] stub, IReadOnlyList<uint> rids)
    {
        var reader = new NdrReader(stub);
        string[] names = ReadReturnedStringArray(reader);
        uint[] uses = ReadUlongArray(reader);

        var result = new List<SamrNameMapping>(rids.Count);
        for (int i = 0; i < rids.Count; i++)
        {
            string name = i < names.Length ? names[i] : string.Empty;
            uint use = i < uses.Length ? uses[i] : 0;
            result.Add(new SamrNameMapping(name, rids[i], use));
        }
        return result;
    }

    /// <summary>
    /// Reads a SAMPR_RETURNED_USTRING_ARRAY (Count + pointer to a conformant array of
    /// RPC_UNICODE_STRING): the fixed headers first, then the deferred (no-NUL) name buffers.
    /// </summary>
    private static string[] ReadReturnedStringArray(NdrReader reader)
    {
        uint count = reader.ReadUInt32();
        uint referent = reader.ReadReferent();
        var names = new string[count];
        if (referent == 0)
        {
            return names;
        }

        reader.ReadUInt32();            // conformant MaxCount
        var refs = new uint[count];
        for (uint i = 0; i < count; i++)
        {
            refs[i] = ReadUnicodeStringHeader(reader); // Length + MaxLength + Buffer referent
        }
        for (uint i = 0; i < count; i++)
        {
            names[i] = refs[i] != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        }
        return names;
    }

    /// <summary>Reads a SAMPR_ULONG_ARRAY (Count + pointer to a conformant array of ULONGs).</summary>
    private static uint[] ReadUlongArray(NdrReader reader)
    {
        uint count = reader.ReadUInt32();
        uint referent = reader.ReadReferent();
        if (referent == 0)
        {
            return Array.Empty<uint>();
        }

        reader.ReadUInt32();            // conformant MaxCount
        var values = new uint[count];
        for (uint i = 0; i < count; i++)
        {
            values[i] = reader.ReadUInt32();
        }
        return values;
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

    /// <summary>
    /// SamrCreateUser2InDomain (opnum 50): create an account in an open domain. Port of impacket's
    /// <c>hSamrCreateUser2InDomain</c> (used by addcomputer.py). For a machine account pass
    /// <paramref name="accountType"/> = <see cref="UserWorkstationTrustAccount"/> and a name ending
    /// in <c>$</c>; the domain handle must have been opened with <see cref="DomainCreateUser"/>. The
    /// account is created DISABLED until a password is set — this is the SAMR account-creation event
    /// a SOC detects. Returns the new user handle, granted access, and RID.
    /// </summary>
    public static SamrCreateUserResult CreateUser2InDomain(
        DcerpcPipe pipe, byte[] domainHandle, string name, uint accountType, uint desiredAccess = MaximumAllowed)
    {
        byte[] stub = pipe.Call(OpnumCreateUser2InDomain, EncodeCreateUser2Request(domainHandle, name, accountType, desiredAccess));

        var reader = new NdrReader(stub);
        byte[] handle = reader.ReadContextHandle();
        uint granted = reader.ReadUInt32();
        uint rid = reader.ReadUInt32();
        uint rc = reader.ReadUInt32();
        return new SamrCreateUserResult(handle, granted, rid, rc);
    }

    /// <summary>
    /// SamrUnicodeChangePasswordUser2 (opnum 55): a user changes their OWN password, proving
    /// knowledge of the old one (no admin rights, no prior handle). Port of impacket's
    /// <c>hSamrUnicodeChangePasswordUser2</c> (the changepasswd.py NetUserChangePassword path).
    /// The new password is RC4-encrypted under the old NT hash; the old NT hash is DES-encrypted
    /// under the new NT hash. Returns the NT status (0 = password changed).
    /// </summary>
    public static uint UnicodeChangePasswordUser2(DcerpcPipe pipe, string userName, string oldPassword, string newPassword)
    {
        byte[] stub = pipe.Call(OpnumUnicodeChangePasswordUser2, EncodeUnicodeChangePassword(userName, oldPassword, newPassword));
        var reader = new NdrReader(stub);
        return reader.ReadUInt32(); // ErrorCode
    }

    /// <summary>
    /// Encodes the SamrUnicodeChangePasswordUser2 request (exposed for tests). Deterministic for
    /// fixed passwords: the password buffers carry no random salt, so the output is reproducible.
    /// </summary>
    public static byte[] EncodeUnicodeChangePassword(string userName, string oldPassword, string newPassword)
    {
        byte[] oldNt = Ntlm.NtlmCrypto.NtHash(oldPassword);
        byte[] newNt = Ntlm.NtlmCrypto.NtHash(newPassword);

        // SAMPR_USER_PASSWORD: Buffer[512] (password right-justified, 'A' fill) + Length (bytes).
        byte[] pwd = System.Text.Encoding.Unicode.GetBytes(newPassword);
        var buffer = new byte[516];
        Array.Fill(buffer, (byte)'A', 0, 512 - pwd.Length);
        Array.Copy(pwd, 0, buffer, 512 - pwd.Length, pwd.Length);
        BitConverter.GetBytes((uint)pwd.Length).CopyTo(buffer, 512);
        byte[] newPwdEncOldNt = Ntlm.NtlmCrypto.Rc4(oldNt, buffer);          // 516 bytes
        byte[] oldNtEncNewNt = Ntlm.NtlmCrypto.SamEncryptNtlmHash(oldNt, newNt); // 16 bytes

        var ndr = new NdrWriter();
        // ServerName: PRPC_UNICODE_STRING -> a single-NUL string.
        ndr.WriteReferent(true);                 // ServerName ptr
        ndr.WriteUInt16(2);                       // Length  (1 char = 2 bytes)
        ndr.WriteUInt16(2);                       // MaximumLength
        ndr.WriteReferent(true);                 // Buffer ptr
        ndr.WriteConformantVaryingString(string.Empty); // -> "\0": max=1,off=0,act=1 + NUL + align
        // UserName: inline RPC_UNICODE_STRING, no trailing NUL.
        ndr.WriteRpcUnicodeStringNoNul(userName);
        // The encrypted password buffers (unique pointers to fixed arrays).
        ndr.WriteReferent(true);
        ndr.WriteBytes(newPwdEncOldNt);
        ndr.WriteReferent(true);
        ndr.WriteBytes(oldNtEncNewNt);
        ndr.WriteByte(0);                         // LmPresent
        ndr.Align(4);
        ndr.WriteReferent(false);                 // NewPasswordEncryptedWithOldLm = NULL
        ndr.WriteReferent(false);                 // OldLmOwfPasswordEncryptedWithNewNt = NULL
        return ndr.ToArray();
    }

    /// <summary>Encodes the SamrCreateUser2InDomain request stub (exposed for tests / offline analysis).</summary>
    public static byte[] EncodeCreateUser2Request(byte[] domainHandle, string name, uint accountType, uint desiredAccess)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(domainHandle);
        ndr.WriteRpcUnicodeStringNoNul(name); // Name (no trailing NUL, as SAMR uses)
        ndr.WriteUInt32(accountType);          // AccountType
        ndr.WriteUInt32(desiredAccess);        // DesiredAccess
        return ndr.ToArray();
    }

    /// <summary>
    /// SamrDeleteUser (opnum 35): delete the account referenced by <paramref name="userHandle"/>.
    /// Port of impacket's <c>hSamrDeleteUser</c>; used here to clean up a lab-created account.
    /// Returns the NT status.
    /// </summary>
    public static uint DeleteUser(DcerpcPipe pipe, byte[] userHandle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(userHandle);
        byte[] stub = pipe.Call(OpnumDeleteUser, ndr.ToArray());

        var reader = new NdrReader(stub);
        reader.ReadContextHandle(); // the (now-null) handle is echoed back
        return reader.ReadUInt32();
    }

    /// <summary>
    /// SamrOpenAlias (opnum 27): open a handle to one alias (local group) by its RID within an
    /// open domain. Port of impacket's <c>hSamrOpenAlias</c>; same request shape as SamrOpenUser.
    /// </summary>
    public static SamrHandleResult OpenAlias(DcerpcPipe pipe, byte[] domainHandle, uint rid, uint desiredAccess = MaximumAllowed)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(domainHandle);
        ndr.WriteUInt32(desiredAccess);
        ndr.WriteUInt32(rid);
        byte[] stub = pipe.Call(OpnumOpenAlias, ndr.ToArray());

        var reader = new NdrReader(stub);
        byte[] handle = reader.ReadContextHandle();
        return new SamrHandleResult(handle, reader.ReadUInt32());
    }

    /// <summary>
    /// SamrGetMembersInAlias (opnum 33): the SIDs that are members of an open alias (local group).
    /// Port of impacket's <c>hSamrGetMembersInAlias</c>. The request is just the alias handle; the
    /// response is a SAMPR_PSID_ARRAY_OUT (Count + a referenced conformant array of
    /// SAMPR_SID_INFORMATION — each a pointer to an RPC_SID).
    /// </summary>
    public static (IReadOnlyList<SamrSid> Members, uint Status) GetMembersInAlias(DcerpcPipe pipe, byte[] aliasHandle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(aliasHandle);
        return ParseMembersInAlias(pipe.Call(OpnumGetMembersInAlias, ndr.ToArray()));
    }

    /// <summary>
    /// Parses a SamrGetMembersInAlias response: a SAMPR_PSID_ARRAY_OUT (Count + a referent to a
    /// conformant SAMPR_SID_INFORMATION array — inline SID-pointer referents, then the deferred
    /// RPC_SIDs in order), then the NTSTATUS. Exposed for tests / offline analysis.
    /// </summary>
    public static (IReadOnlyList<SamrSid> Members, uint Status) ParseMembersInAlias(byte[] stub)
    {
        var reader = new NdrReader(stub);
        uint count = reader.ReadUInt32();     // Count
        if (reader.ReadReferent() == 0)       // Sids array pointer
        {
            return (Array.Empty<SamrSid>(), reader.ReadUInt32());
        }

        reader.ReadUInt32();                  // conformant max_count

        // Inline SAMPR_SID_INFORMATION.SidPointer referents first.
        var sidRefs = new uint[count];
        for (uint i = 0; i < count; i++)
        {
            sidRefs[i] = reader.ReadReferent();
        }

        // Then the deferred RPC_SIDs, in order.
        var members = new List<SamrSid>((int)count);
        for (uint i = 0; i < count; i++)
        {
            if (sidRefs[i] != 0)
            {
                members.Add(ReadSid(reader));
            }
        }

        uint status = reader.ReadUInt32();    // ErrorCode (NTSTATUS)
        return (members, status);
    }

    /// <summary>
    /// SamrGetGroupsForUser (opnum 39): the domain groups a user is a member of, as
    /// GROUP_MEMBERSHIP rows (RID + SE_GROUP_* attributes). Port of impacket's
    /// <c>hSamrGetGroupsForUser</c>. The request is just the user handle; the response is a
    /// SAMPR_GET_GROUPS_BUFFER (count + pointer to a conformant GROUP_MEMBERSHIP array).
    /// </summary>
    public static IReadOnlyList<SamrGroupMembership> GetGroupsForUser(DcerpcPipe pipe, byte[] userHandle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(userHandle);
        byte[] stub = pipe.Call(OpnumGetGroupsForUser, ndr.ToArray());
        return ParseGroupsForUser(stub);
    }

    /// <summary>Parses a SamrGetGroupsForUser response (exposed for tests / offline analysis).</summary>
    public static IReadOnlyList<SamrGroupMembership> ParseGroupsForUser(byte[] stub)
    {
        var reader = new NdrReader(stub);
        uint bufferReferent = reader.ReadReferent();
        if (bufferReferent == 0)
        {
            return Array.Empty<SamrGroupMembership>();
        }

        uint count = reader.ReadUInt32();     // MembershipCount
        uint arrayReferent = reader.ReadReferent();
        var groups = new List<SamrGroupMembership>((int)count);
        if (arrayReferent != 0)
        {
            reader.ReadUInt32();              // conformant MaxCount
            for (uint i = 0; i < count; i++)
            {
                uint rid = reader.ReadUInt32();
                uint attributes = reader.ReadUInt32();
                groups.Add(new SamrGroupMembership(rid, attributes));
            }
        }
        return groups;
    }

    private static readonly (uint Bit, string Name)[] GroupAttributeFlags =
    {
        (0x00000001, "MANDATORY"),
        (0x00000002, "ENABLED_BY_DEFAULT"),
        (0x00000004, "ENABLED"),
        (0x00000008, "OWNER"),
        (0x00000010, "USE_FOR_DENY_ONLY"),
        (0x00000020, "INTEGRITY"),
        (0x00000040, "INTEGRITY_ENABLED"),
        (0x20000000, "RESOURCE"),
    };

    /// <summary>Renders the SE_GROUP_* attribute flag names set in a GROUP_MEMBERSHIP.Attributes value.</summary>
    public static string GroupAttributesText(uint attributes)
    {
        var set = GroupAttributeFlags.Where(f => (attributes & f.Bit) != 0).Select(f => f.Name).ToArray();
        return set.Length == 0 ? "(none)" : string.Join(" | ", set);
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

    /// <summary>
    /// SamrQueryDisplayInformation (opnum 40), class DomainDisplayUser (1): the account display
    /// list samrdump prints — RID, account-control flags, name, description and full name for
    /// every user in one enumeration. Port of impacket's <c>hSamrQueryDisplayInformation</c>.
    /// Continues across pages on STATUS_MORE_ENTRIES (resuming from the last returned Index).
    /// </summary>
    public static IReadOnlyList<SamrDisplayUser> QueryDisplayUsers(DcerpcPipe pipe, byte[] domainHandle)
    {
        var all = new List<SamrDisplayUser>();
        uint index = 0;
        while (true)
        {
            var ndr = new NdrWriter();
            ndr.WriteContextHandle(domainHandle);   // DomainHandle [in]
            ndr.WriteUInt32(DomainDisplayUser);      // DisplayInformationClass = 1
            ndr.WriteUInt32(index);                  // Index [in] — resume point
            ndr.WriteUInt32(0xFFFFFFFF);             // EntryCount — "as many as fit"
            ndr.WriteUInt32(0xFFFFFFFF);             // PreferredMaximumLength — "everything"
            byte[] stub = pipe.Call(OpnumQueryDisplayInformation, ndr.ToArray());

            (IReadOnlyList<SamrDisplayUser> page, _, uint status) = ParseDisplayUsers(stub);
            all.AddRange(page);

            // Single-shot on this lab (server returns all with status 0). Only page when the
            // server explicitly says there is more; resume just past the last Index we saw.
            if (page.Count == 0 || status != StatusMoreEntries)
            {
                break;
            }

            index = page[^1].Index;
        }

        return all;
    }

    /// <summary>
    /// Parses a SamrQueryDisplayInformation DomainDisplayUser response: TotalAvailable,
    /// TotalReturned, a SAMPR_DISPLAY_INFO_BUFFER union (tag 1 -> EntriesRead + a referenced
    /// conformant SAMPR_DOMAIN_DISPLAY_USER array: Index/Rid/AccountControl + three
    /// RPC_UNICODE_STRING headers each, then the deferred name/description/full-name buffers),
    /// then the NTSTATUS. Returns the page, TotalAvailable, and the status. Exposed for tests.
    /// </summary>
    public static (IReadOnlyList<SamrDisplayUser> Users, uint TotalAvailable, uint Status) ParseDisplayUsers(byte[] stub)
    {
        var reader = new NdrReader(stub);
        uint totalAvailable = reader.ReadUInt32();  // TotalAvailable
        reader.ReadUInt32();                         // TotalReturned (bytes)
        reader.ReadUInt32();                         // union discriminant (DisplayInformationClass == 1)
        uint entries = reader.ReadUInt32();          // EntriesRead
        if (reader.ReadReferent() == 0)              // Buffer array pointer
        {
            return (Array.Empty<SamrDisplayUser>(), totalAvailable, reader.ReadUInt32());
        }

        reader.ReadUInt32();                         // conformant max_count

        // Inline fixed fields + the three RPC_UNICODE_STRING headers per entry.
        var index = new uint[entries];
        var rid = new uint[entries];
        var ctrl = new uint[entries];
        var nameRef = new uint[entries];
        var commentRef = new uint[entries];
        var fullRef = new uint[entries];
        for (uint i = 0; i < entries; i++)
        {
            index[i] = reader.ReadUInt32();          // Index
            rid[i] = reader.ReadUInt32();            // Rid
            ctrl[i] = reader.ReadUInt32();           // AccountControl
            nameRef[i] = ReadUnicodeStringHeader(reader);    // AccountName
            commentRef[i] = ReadUnicodeStringHeader(reader); // AdminComment
            fullRef[i] = ReadUnicodeStringHeader(reader);    // FullName
        }

        // Deferred conformant-varying buffers, in field order per entry.
        var users = new List<SamrDisplayUser>((int)entries);
        for (uint i = 0; i < entries; i++)
        {
            string name = nameRef[i] != 0 ? reader.ReadConformantVaryingString() : string.Empty;
            string comment = commentRef[i] != 0 ? reader.ReadConformantVaryingString() : string.Empty;
            string full = fullRef[i] != 0 ? reader.ReadConformantVaryingString() : string.Empty;
            users.Add(new SamrDisplayUser(index[i], rid[i], ctrl[i], name, comment, full));
        }

        uint status = reader.ReadUInt32();           // ErrorCode (NTSTATUS)
        return (users, totalAvailable, status);
    }

    /// <summary>
    /// SamrQueryDisplayInformation (opnum 40), class DomainDisplayGroup (3): the domain group
    /// display list — RID, SE_GROUP_* attributes, name and description for every group in one
    /// enumeration. Same call as <see cref="QueryDisplayUsers"/> with a different information class;
    /// the per-entry record is a SAMPR_DOMAIN_DISPLAY_GROUP (no FullName field).
    /// </summary>
    public static IReadOnlyList<SamrDisplayGroup> QueryDisplayGroups(DcerpcPipe pipe, byte[] domainHandle)
    {
        var all = new List<SamrDisplayGroup>();
        uint index = 0;
        while (true)
        {
            var ndr = new NdrWriter();
            ndr.WriteContextHandle(domainHandle);   // DomainHandle [in]
            ndr.WriteUInt32(DomainDisplayGroup);     // DisplayInformationClass = 3
            ndr.WriteUInt32(index);                  // Index [in] — resume point
            ndr.WriteUInt32(0xFFFFFFFF);             // EntryCount — "as many as fit"
            ndr.WriteUInt32(0xFFFFFFFF);             // PreferredMaximumLength — "everything"
            byte[] stub = pipe.Call(OpnumQueryDisplayInformation, ndr.ToArray());

            (IReadOnlyList<SamrDisplayGroup> page, _, uint status) = ParseDisplayGroups(stub);
            all.AddRange(page);

            if (page.Count == 0 || status != StatusMoreEntries)
            {
                break;
            }

            index = page[^1].Index;
        }

        return all;
    }

    /// <summary>
    /// Parses a SamrQueryDisplayInformation DomainDisplayGroup response: TotalAvailable,
    /// TotalReturned, a SAMPR_DISPLAY_INFO_BUFFER union (tag 3 -> EntriesRead + a referenced
    /// conformant SAMPR_DOMAIN_DISPLAY_GROUP array: Index/Rid/Attributes + two RPC_UNICODE_STRING
    /// headers each, then the deferred name/description buffers), then the NTSTATUS. Exposed for tests.
    /// </summary>
    public static (IReadOnlyList<SamrDisplayGroup> Groups, uint TotalAvailable, uint Status) ParseDisplayGroups(byte[] stub)
    {
        var reader = new NdrReader(stub);
        uint totalAvailable = reader.ReadUInt32();  // TotalAvailable
        reader.ReadUInt32();                         // TotalReturned (bytes)
        reader.ReadUInt32();                         // union discriminant (DisplayInformationClass == 3)
        uint entries = reader.ReadUInt32();          // EntriesRead
        if (reader.ReadReferent() == 0)              // Buffer array pointer
        {
            return (Array.Empty<SamrDisplayGroup>(), totalAvailable, reader.ReadUInt32());
        }

        reader.ReadUInt32();                         // conformant max_count

        var index = new uint[entries];
        var rid = new uint[entries];
        var attributes = new uint[entries];
        var nameRef = new uint[entries];
        var commentRef = new uint[entries];
        for (uint i = 0; i < entries; i++)
        {
            index[i] = reader.ReadUInt32();          // Index
            rid[i] = reader.ReadUInt32();            // Rid
            attributes[i] = reader.ReadUInt32();     // Attributes (SE_GROUP_*)
            nameRef[i] = ReadUnicodeStringHeader(reader);    // AccountName
            commentRef[i] = ReadUnicodeStringHeader(reader); // AdminComment
        }

        var groups = new List<SamrDisplayGroup>((int)entries);
        for (uint i = 0; i < entries; i++)
        {
            string name = nameRef[i] != 0 ? reader.ReadConformantVaryingString() : string.Empty;
            string comment = commentRef[i] != 0 ? reader.ReadConformantVaryingString() : string.Empty;
            groups.Add(new SamrDisplayGroup(index[i], rid[i], attributes[i], name, comment));
        }

        uint status = reader.ReadUInt32();           // ErrorCode (NTSTATUS)
        return (groups, totalAvailable, status);
    }

    /// <summary>
    /// SamrQueryInformationDomain (opnum 8), class DomainGeneralInformation (level 2): the domain's
    /// name, server role/state, and live user/group/alias object counts. Port of impacket's
    /// <c>hSamrQueryInformationDomain</c> at this level.
    /// </summary>
    public static SamrDomainGeneral QueryDomainGeneralInfo(DcerpcPipe pipe, byte[] domainHandle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(domainHandle);
        ndr.WriteUInt16(DomainGeneralInformation);
        return ParseDomainGeneral(pipe.Call(OpnumQueryInformationDomain, ndr.ToArray()));
    }

    /// <summary>
    /// Parses a DomainGeneralInformation response buffer: referent + union tag (2), a
    /// SAMPR_DOMAIN_GENERAL_INFORMATION (ForceLogoff; three RPC_UNICODE_STRING headers for
    /// Oem/DomainName/ReplicaSource; DomainModifiedCount; ServerState; ServerRole; a UCHAR
    /// UAS-compat flag; and the User/Group/Alias counts), then the deferred string buffers in
    /// field order, then the NTSTATUS. Exposed for tests / offline analysis.
    /// </summary>
    public static SamrDomainGeneral ParseDomainGeneral(byte[] stub)
    {
        var reader = new NdrReader(stub);
        reader.ReadReferent();                 // Buffer pointer
        reader.ReadUInt32();                   // union discriminant (== 2)

        long forceLogoff = reader.ReadInt64(); // ForceLogoff (relative time)
        uint oemRef = ReadUnicodeStringHeader(reader);     // OemInformation
        uint nameRef = ReadUnicodeStringHeader(reader);    // DomainName
        uint replicaRef = ReadUnicodeStringHeader(reader); // ReplicaSourceNodeName
        long modifiedCount = reader.ReadInt64();           // DomainModifiedCount
        uint serverState = reader.ReadUInt32();            // DomainServerState
        uint serverRole = reader.ReadUInt32();             // DomainServerRole
        bool uas = reader.ReadByte() != 0;                 // UasCompatibilityRequired (UCHAR)
        uint userCount = reader.ReadUInt32();              // UserCount (ReadUInt32 realigns past the UCHAR pad)
        uint groupCount = reader.ReadUInt32();             // GroupCount
        uint aliasCount = reader.ReadUInt32();             // AliasCount

        // Deferred conformant-varying buffers, in field order.
        string oem = oemRef != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        string name = nameRef != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        string replica = replicaRef != 0 ? reader.ReadConformantVaryingString() : string.Empty;

        uint status = reader.ReadUInt32();     // ErrorCode (NTSTATUS)
        return new SamrDomainGeneral(
            name, oem, replica, serverState, serverRole, uas,
            userCount, groupCount, aliasCount, forceLogoff, modifiedCount, status);
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
