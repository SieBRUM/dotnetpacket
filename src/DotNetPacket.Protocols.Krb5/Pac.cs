using System.Text;
using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>A single entry in the PAC buffer table (MS-PAC 2.4 PAC_INFO_BUFFER).</summary>
public sealed record PacBuffer(uint Type, uint Size, ulong Offset);

/// <summary>A group membership from KERB_VALIDATION_INFO (a RID + its SE_GROUP attributes).</summary>
public sealed record PacGroup(uint Rid, uint Attributes);

/// <summary>
/// The high-signal fields of KERB_VALIDATION_INFO (MS-PAC 2.5) — the logon identity a ticket asserts.
/// This is the PAC content golden/silver-ticket detection keys on: the account RID, the primary group,
/// the group RIDs, and any ExtraSids (SID history / injected SIDs such as Enterprise Admins).
/// </summary>
public sealed record PacLogonInfo(
    string EffectiveName,
    string FullName,
    string LogonDomainName,
    string LogonServer,
    string? LogonDomainSid,
    uint UserId,
    uint PrimaryGroupId,
    uint UserAccountControl,
    uint UserFlags,
    DateTimeOffset? LogonTime,
    IReadOnlyList<PacGroup> Groups,
    IReadOnlyList<string> ExtraSids);

/// <summary>PAC_CLIENT_INFO (MS-PAC 2.7): the client name + the KDC-stamped authentication time.</summary>
public sealed record PacClientInfo(DateTimeOffset? ClientId, string Name);

/// <summary>PAC_SIGNATURE_DATA (MS-PAC 2.8): a server or KDC checksum over the PAC.</summary>
public sealed record PacSignature(int Type, byte[] Signature);

/// <summary>UPN_DNS_INFO (MS-PAC 2.10): the client UPN and the DNS domain name.</summary>
public sealed record PacUpnDnsInfo(string Upn, string DnsDomainName);

/// <summary>
/// Result of verifying a PAC's two signatures (MS-PAC 2.8 / [MS-KILE] 3.4.5.3). <see cref="ServerOk"/>
/// is the SERVER_CHECKSUM over the whole PAC under the service key; <see cref="KdcOk"/> is the
/// KDC/PRIVSVR checksum over the server signature under the krbtgt key (null when no krbtgt key was
/// supplied). A genuine KDC-issued PAC passes both; a hand-forged one (e.g. a golden ticket built
/// without the real keys) fails them — the core forged-PAC detection.
/// </summary>
public sealed record PacVerifyResult(bool ServerOk, bool? KdcOk, int ServerType, int KdcType);

/// <summary>A parsed PAC: the buffer table plus the decoded buffers we understand.</summary>
public sealed record PacInfo(
    uint Version,
    IReadOnlyList<PacBuffer> Buffers,
    PacLogonInfo? LogonInfo,
    PacClientInfo? ClientInfo,
    PacSignature? ServerChecksum,
    PacSignature? KdcChecksum,
    PacUpnDnsInfo? UpnDnsInfo);

/// <summary>
/// Parser for the Privilege Attribute Certificate ([MS-PAC]) carried in a Kerberos ticket's
/// authorization-data (AD-WIN2K-PAC, ad-type 128). Port of impacket's <c>impacket/krb5/pac.py</c>
/// structures (PACTYPE / PAC_INFO_BUFFER / KERB_VALIDATION_INFO / PAC_CLIENT_INFO / PAC_SIGNATURE_DATA /
/// UPN_DNS_INFO). The KERB_VALIDATION_INFO buffer is NDR (type-serialization v1); it is decoded here by
/// hand on <see cref="ByteReader"/> so this module stays free of the DCERPC NDR stack (which depends on
/// Krb5). Decode-only and lab-first: the PAC is the identity a SOC inspects to spot forged/over-privileged
/// tickets, so the goal is faithful, inspectable parsing — not minting PACs.
/// </summary>
public static class Pac
{
    public const uint LogonInfo = 1;
    public const uint ServerChecksum = 6;
    public const uint PrivSvrChecksum = 7;
    public const uint ClientInfo = 10;
    public const uint UpnDnsInfo = 12;

    private const int KerbNonKerbCksumSalt = 17; // key usage for the PAC signatures ([MS-KILE] 3.4.5.3)

    // PAC checksum (SignatureType) values -> the etype whose keyed checksum computes them.
    private const int ChecksumHmacMd5 = -138;       // KERB_CHECKSUM_HMAC_MD5 (RC4 keys)
    private const int ChecksumHmacSha1Aes128 = 15;  // HMAC_SHA1_96_AES128
    private const int ChecksumHmacSha1Aes256 = 16;  // HMAC_SHA1_96_AES256

    /// <summary>
    /// Verifies the PAC's SERVER_CHECKSUM (under <paramref name="serverKey"/>, the key the ticket is
    /// encrypted with) and, when <paramref name="krbtgtKey"/> is given, the KDC/PRIVSVR checksum (under
    /// the krbtgt key). Procedure per [MS-KILE] 3.4.5.3 / impacket <c>sign_pac</c>: zero both signature
    /// fields, HMAC the whole PAC for the server signature, then HMAC that server signature for the KDC
    /// signature — both at key usage 17. The key etype must match the stored SignatureType (RC4 key for
    /// HMAC-MD5, AES key for HMAC-SHA1-96).
    /// </summary>
    public static PacVerifyResult Verify(byte[] pac, byte[] serverKey, byte[]? krbtgtKey)
    {
        var r = new ByteReader(pac, ByteOrder.Little);
        uint cBuffers = r.ReadUInt32();
        r.ReadUInt32(); // version
        (int Off, int Size) server = default, kdc = default;
        for (uint i = 0; i < cBuffers && r.Remaining >= 16; i++)
        {
            uint type = r.ReadUInt32();
            int size = (int)r.ReadUInt32();
            int off = (int)r.ReadUInt64();
            if (type == ServerChecksum) server = (off, size);
            else if (type == PrivSvrChecksum) kdc = (off, size);
        }

        if (server.Size < 4 || kdc.Size < 4)
        {
            throw new InvalidOperationException("PAC is missing a server or KDC checksum buffer.");
        }

        int serverType = BitConverter.ToInt32(pac, server.Off);
        int kdcType = BitConverter.ToInt32(pac, kdc.Off);
        byte[] storedServerSig = pac[(server.Off + 4)..(server.Off + server.Size)];
        byte[] storedKdcSig = pac[(kdc.Off + 4)..(kdc.Off + kdc.Size)];

        // Both signature fields are zeroed before the server signature is computed over the whole PAC.
        byte[] zeroed = (byte[])pac.Clone();
        Array.Clear(zeroed, server.Off + 4, server.Size - 4);
        Array.Clear(zeroed, kdc.Off + 4, kdc.Size - 4);

        byte[] computedServer = Krb5Cipher.Checksum(EtypeForChecksum(serverType), serverKey, KerbNonKerbCksumSalt, zeroed);
        bool serverOk = computedServer.AsSpan().SequenceEqual(storedServerSig);

        bool? kdcOk = null;
        if (krbtgtKey is not null)
        {
            byte[] computedKdc = Krb5Cipher.Checksum(EtypeForChecksum(kdcType), krbtgtKey, KerbNonKerbCksumSalt, storedServerSig);
            kdcOk = computedKdc.AsSpan().SequenceEqual(storedKdcSig);
        }

        return new PacVerifyResult(serverOk, kdcOk, serverType, kdcType);
    }

    private static int EtypeForChecksum(int signatureType) => signatureType switch
    {
        ChecksumHmacMd5 => Krb5Constants.Rc4Hmac,
        ChecksumHmacSha1Aes128 => Krb5Constants.Aes128CtsHmacSha1,
        ChecksumHmacSha1Aes256 => Krb5Constants.Aes256CtsHmacSha1,
        _ => throw new NotSupportedException($"Unsupported PAC checksum type {signatureType}."),
    };

    /// <summary>Parses a PAC blob (PACTYPE header + buffer table + the buffers we decode).</summary>
    public static PacInfo Parse(byte[] pac)
    {
        var r = new ByteReader(pac, ByteOrder.Little);
        uint cBuffers = r.ReadUInt32();
        uint version = r.ReadUInt32();

        var buffers = new List<PacBuffer>();
        for (uint i = 0; i < cBuffers && r.Remaining >= 16; i++)
        {
            uint type = r.ReadUInt32();
            uint size = r.ReadUInt32();
            ulong offset = r.ReadUInt64();
            buffers.Add(new PacBuffer(type, size, offset));
        }

        PacLogonInfo? logon = null;
        PacClientInfo? client = null;
        PacSignature? server = null;
        PacSignature? kdc = null;
        PacUpnDnsInfo? upn = null;

        foreach (PacBuffer b in buffers)
        {
            if (b.Offset + b.Size > (ulong)pac.Length)
            {
                continue; // malformed offset/size; skip rather than throw
            }

            byte[] slice = pac[(int)b.Offset..(int)(b.Offset + b.Size)];
            try
            {
                switch (b.Type)
                {
                    case LogonInfo: logon = ParseLogonInfo(slice); break;
                    case ClientInfo: client = ParseClientInfo(slice); break;
                    case ServerChecksum: server = ParseSignature(slice); break;
                    case PrivSvrChecksum: kdc = ParseSignature(slice); break;
                    case UpnDnsInfo: upn = ParseUpnDnsInfo(slice); break;
                }
            }
            catch
            {
                // A single malformed buffer must not sink the whole parse; leave that field null.
            }
        }

        return new PacInfo(version, buffers, logon, client, server, kdc, upn);
    }

    // ---- KERB_VALIDATION_INFO (NDR type-serialization v1) ---------------------------------------

    private static PacLogonInfo ParseLogonInfo(byte[] buf)
    {
        var r = new ByteReader(buf, ByteOrder.Little);

        // CommonTypeHeader (8): Version=1, Endianness=0x10 (LE), HeaderLength=8, Filler. PrivateTypeHeader
        // (8): ObjectBufferLength, Filler. Then the top-level pointer's referent id (4).
        r.ReadBytes(8);
        r.ReadBytes(8);
        r.ReadUInt32(); // root referent id (non-zero)

        DateTimeOffset? logonTime = ReadFileTime(r);
        ReadFileTime(r); // LogoffTime
        ReadFileTime(r); // KickOffTime
        ReadFileTime(r); // PasswordLastSet
        ReadFileTime(r); // PasswordCanChange
        ReadFileTime(r); // PasswordMustChange

        (int effLen, uint effRef) = ReadStringHeader(r);
        (int fullLen, uint fullRef) = ReadStringHeader(r);
        (int scriptLen, uint scriptRef) = ReadStringHeader(r);
        (int profLen, uint profRef) = ReadStringHeader(r);
        (int homeLen, uint homeRef) = ReadStringHeader(r);
        (int homeDrvLen, uint homeDrvRef) = ReadStringHeader(r);

        r.ReadUInt16(); // LogonCount
        r.ReadUInt16(); // BadPasswordCount
        uint userId = r.ReadUInt32();
        uint primaryGroupId = r.ReadUInt32();
        uint groupCount = r.ReadUInt32();
        uint groupRef = r.ReadUInt32();
        uint userFlags = r.ReadUInt32();
        r.ReadBytes(16); // UserSessionKey

        (int srvLen, uint srvRef) = ReadStringHeader(r);
        (int domLen, uint domRef) = ReadStringHeader(r);
        uint logonDomainIdRef = r.ReadUInt32();
        r.ReadBytes(8); // LMKey / Reserved1
        uint uac = r.ReadUInt32();
        r.ReadUInt32(); // SubAuthStatus
        ReadFileTime(r); // LastSuccessfulILogon
        ReadFileTime(r); // LastFailedILogon
        r.ReadUInt32(); // FailedILogonCount
        r.ReadUInt32(); // Reserved3
        uint sidCount = r.ReadUInt32();
        uint extraSidsRef = r.ReadUInt32();
        r.ReadUInt32(); // ResourceGroupDomainSid referent
        r.ReadUInt32(); // ResourceGroupCount
        r.ReadUInt32(); // ResourceGroupIds referent

        // ---- deferred referents, in field order ----
        string effName = ReadString(r, effRef, effLen);
        string fullName = ReadString(r, fullRef, fullLen);
        ReadString(r, scriptRef, scriptLen);
        ReadString(r, profRef, profLen);
        ReadString(r, homeRef, homeLen);
        ReadString(r, homeDrvRef, homeDrvLen);

        var groups = new List<PacGroup>();
        if (groupRef != 0)
        {
            uint max = r.ReadUInt32();
            for (uint i = 0; i < max; i++)
            {
                uint rid = r.ReadUInt32();
                uint attr = r.ReadUInt32();
                groups.Add(new PacGroup(rid, attr));
            }
        }

        string logonServer = ReadString(r, srvRef, srvLen);
        string logonDomain = ReadString(r, domRef, domLen);

        string? domainSid = logonDomainIdRef != 0 ? ReadSid(r) : null;

        var extraSids = new List<string>();
        if (extraSidsRef != 0)
        {
            uint max = r.ReadUInt32();
            var attrs = new uint[max];
            var refs = new uint[max];
            for (uint i = 0; i < max; i++)
            {
                refs[i] = r.ReadUInt32();   // Sid referent
                attrs[i] = r.ReadUInt32();  // Attributes
            }

            for (uint i = 0; i < max; i++)
            {
                if (refs[i] != 0)
                {
                    extraSids.Add(ReadSid(r));
                }
            }
        }

        return new PacLogonInfo(effName, fullName, logonDomain, logonServer, domainSid, userId,
            primaryGroupId, uac, userFlags, logonTime, groups, extraSids);
    }

    /// <summary>Reads an RPC_UNICODE_STRING header (Length, MaxLength, Buffer referent).</summary>
    private static (int Length, uint Referent) ReadStringHeader(ByteReader r)
    {
        int length = r.ReadUInt16();
        r.ReadUInt16();            // MaximumLength
        uint referent = r.ReadUInt32();
        return (length, referent);
    }

    /// <summary>Reads a deferred conformant-varying wchar buffer (MaxCount, Offset, ActualCount, chars).</summary>
    private static string ReadString(ByteReader r, uint referent, int byteLength)
    {
        if (referent == 0)
        {
            return string.Empty;
        }

        r.ReadUInt32(); // MaxCount
        r.ReadUInt32(); // Offset
        uint actual = r.ReadUInt32();
        byte[] chars = r.ReadBytes((int)actual * 2);
        Align4(r);
        // byteLength is the Length field (bytes actually used); trust ActualCount for the read.
        _ = byteLength;
        return Encoding.Unicode.GetString(chars);
    }

    /// <summary>Reads an NDR RPC_SID (conformant) and formats it S-1-… (MS-DTYP).</summary>
    private static string ReadSid(ByteReader r)
    {
        uint count = r.ReadUInt32();  // conformant max_count == SubAuthorityCount
        byte revision = r.ReadBytes(1)[0];
        byte subCount = r.ReadBytes(1)[0];
        byte[] idAuth = r.ReadBytes(6); // big-endian 48-bit authority
        ulong authority = 0;
        foreach (byte x in idAuth)
        {
            authority = (authority << 8) | x;
        }

        var sb = new StringBuilder($"S-{revision}-{authority}");
        uint n = Math.Max(count, subCount);
        for (uint i = 0; i < n; i++)
        {
            sb.Append('-').Append(r.ReadUInt32());
        }

        return sb.ToString();
    }

    // ---- simple (non-NDR) buffers ---------------------------------------------------------------

    private static PacClientInfo ParseClientInfo(byte[] buf)
    {
        var r = new ByteReader(buf, ByteOrder.Little);
        DateTimeOffset? clientId = ReadFileTime(r);
        int nameLen = r.ReadUInt16();
        string name = Encoding.Unicode.GetString(r.ReadBytes(nameLen));
        return new PacClientInfo(clientId, name);
    }

    private static PacSignature ParseSignature(byte[] buf)
    {
        var r = new ByteReader(buf, ByteOrder.Little);
        int type = r.ReadInt32();
        byte[] sig = r.ReadBytes(r.Remaining);
        return new PacSignature(type, sig);
    }

    private static PacUpnDnsInfo ParseUpnDnsInfo(byte[] buf)
    {
        var r = new ByteReader(buf, ByteOrder.Little);
        int upnLen = r.ReadUInt16();
        int upnOff = r.ReadUInt16();
        int dnsLen = r.ReadUInt16();
        int dnsOff = r.ReadUInt16();
        string upn = upnOff + upnLen <= buf.Length ? Encoding.Unicode.GetString(buf, upnOff, upnLen) : string.Empty;
        string dns = dnsOff + dnsLen <= buf.Length ? Encoding.Unicode.GetString(buf, dnsOff, dnsLen) : string.Empty;
        return new PacUpnDnsInfo(upn, dns);
    }

    // ---- helpers --------------------------------------------------------------------------------

    private static DateTimeOffset? ReadFileTime(ByteReader r)
    {
        ulong low = r.ReadUInt32();
        ulong high = r.ReadUInt32();
        ulong ft = (high << 32) | low;
        if (ft == 0 || ft == 0x7FFFFFFFFFFFFFFF)
        {
            return null; // "no time set" / "never"
        }

        // FILETIME: 100-ns ticks since 1601-01-01 UTC.
        return new DateTimeOffset(1601, 1, 1, 0, 0, 0, TimeSpan.Zero).AddTicks((long)ft);
    }

    private static void Align4(ByteReader r)
    {
        int m = r.Position % 4;
        if (m != 0)
        {
            r.ReadBytes(4 - m);
        }
    }
}
