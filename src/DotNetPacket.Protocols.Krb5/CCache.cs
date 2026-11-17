using System.Buffers.Binary;
using System.Text;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>One credential in a ccache: the principals, session key, lifetime, flags and the ticket.</summary>
public sealed record CcacheCredential(
    string ClientName, string ClientRealm,
    string ServerName, string ServerRealm,
    int KeyType, byte[] Key,
    DateTimeOffset AuthTime, DateTimeOffset StartTime, DateTimeOffset EndTime, DateTimeOffset RenewTill,
    byte[] Flags, byte[] Ticket);

/// <summary>Parsed ccache: the default principal and its credentials.</summary>
public sealed record CCacheFile(string DefaultClient, string DefaultRealm, IReadOnlyList<CcacheCredential> Credentials);

/// <summary>
/// Reads and writes the MIT Kerberos credential cache (ccache) file format, version 4 — the
/// <c>KRB5CCNAME</c> ticket store that impacket's <c>-k</c> is driven by. Port of
/// <c>impacket.krb5.ccache.CCache</c>: a 0x0504 mini-header, one DeltaTime header, a default
/// principal, then a sequence of credentials (client/server principals, keyblock, times, flags,
/// ticket). All integers are big-endian. This lets DotNetPacket's tickets (getTGT / getST) interoperate
/// with the MIT/impacket toolchain and lets <c>-k</c> consume a ccache produced elsewhere.
/// </summary>
public static class CCache
{
    private const ushort FileFormatVersion = 0x0504;
    private const int NtPrincipal = 1;
    private const int NtSrvInst = 2;

    /// <summary>Serializes a ccache: the default principal plus <paramref name="creds"/>.</summary>
    public static byte[] Build(string defaultClient, string defaultRealm, IReadOnlyList<CcacheCredential> creds)
    {
        var ms = new MemoryStream();
        WriteU16(ms, FileFormatVersion);
        WriteU16(ms, 12);                                   // header length
        WriteU16(ms, 1);                                    // header tag = DeltaTime
        WriteU16(ms, 8);                                    // taglen
        ms.Write(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0 });

        WritePrincipal(ms, NtPrincipal, defaultClient, defaultRealm);

        foreach (CcacheCredential c in creds)
        {
            WritePrincipal(ms, NtPrincipal, c.ClientName, c.ClientRealm);     // client
            WritePrincipal(ms, NtSrvInst, c.ServerName, c.ServerRealm);       // server
            WriteU16(ms, (ushort)c.KeyType);                                  // keyblock: keytype
            WriteU16(ms, 0);                                                  //           etype (unused in v4)
            WriteU16(ms, (ushort)c.Key.Length);
            ms.Write(c.Key);
            WriteU32(ms, ToUnix(c.AuthTime));                                 // times
            WriteU32(ms, ToUnix(c.StartTime));
            WriteU32(ms, ToUnix(c.EndTime));
            WriteU32(ms, ToUnix(c.RenewTill));
            ms.WriteByte(0);                                                  // is_skey
            ms.Write(FourByteFlags(c.Flags));                                 // tktflags (big-endian u32)
            WriteU32(ms, 0);                                                  // num_address
            WriteU32(ms, 0);                                                  // num_authdata
            WriteCountedOctetString(ms, c.Ticket);                           // ticket
            WriteCountedOctetString(ms, Array.Empty<byte>());               // second ticket
        }

        return ms.ToArray();
    }

    /// <summary>Parses a ccache file's bytes.</summary>
    public static CCacheFile Parse(byte[] data)
    {
        int p = 0;
        ushort version = ReadU16(data, ref p);
        if (version != FileFormatVersion)
        {
            throw new NotSupportedException($"ccache version 0x{version:X4} not supported (only 0x0504 / v4).");
        }

        int headerLen = ReadU16(data, ref p);
        p += headerLen;                                      // skip headers (DeltaTime etc.)

        (string defClient, string defRealm) = ReadPrincipal(data, ref p);

        var creds = new List<CcacheCredential>();
        while (p < data.Length)
        {
            (string clientName, string clientRealm) = ReadPrincipal(data, ref p);
            (string serverName, string serverRealm) = ReadPrincipal(data, ref p);
            int keyType = ReadU16(data, ref p);
            p += 2;                                          // etype (unused)
            int keyLen = ReadU16(data, ref p);
            byte[] key = data[p..(p + keyLen)];
            p += keyLen;
            DateTimeOffset auth = FromUnix(ReadU32(data, ref p));
            DateTimeOffset start = FromUnix(ReadU32(data, ref p));
            DateTimeOffset end = FromUnix(ReadU32(data, ref p));
            DateTimeOffset renew = FromUnix(ReadU32(data, ref p));
            p += 1;                                          // is_skey
            byte[] flags = data[p..(p + 4)];
            p += 4;
            SkipTaggedList(data, ref p);                     // addresses
            SkipTaggedList(data, ref p);                     // authdata
            byte[] ticket = ReadCountedOctetString(data, ref p);
            ReadCountedOctetString(data, ref p);             // second ticket

            // Skip the config pseudo-credentials impacket stores (server realm "X-CACHECONF:").
            if (serverRealm != "X-CACHECONF:")
            {
                creds.Add(new CcacheCredential(clientName, clientRealm, serverName, serverRealm,
                    keyType, key, auth, start, end, renew, flags, ticket));
            }
        }

        return new CCacheFile(defClient, defRealm, creds);
    }

    /// <summary>Builds a ccache credential from a TGT.</summary>
    public static CcacheCredential FromTgt(Tgt tgt)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new CcacheCredential(
            tgt.User, tgt.Realm, tgt.ServiceName, tgt.Realm,
            tgt.SessionKeyEtype, tgt.SessionKey,
            tgt.AuthTime ?? now, tgt.StartTime ?? now, tgt.EndTime ?? now.AddHours(10), tgt.RenewTill ?? DateTimeOffset.UnixEpoch,
            tgt.TicketFlags ?? new byte[4], tgt.Ticket);
    }

    /// <summary>Builds a ccache credential from a service ticket (the server is its SPN).</summary>
    public static CcacheCredential FromServiceTicket(ServiceTicket st)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new CcacheCredential(
            st.User, st.Realm, st.ServerName ?? "unknown", st.Realm,
            st.SessionKeyEtype, st.SessionKey,
            st.AuthTime ?? now, st.StartTime ?? now, st.EndTime ?? now.AddHours(10), st.RenewTill ?? DateTimeOffset.UnixEpoch,
            st.Flags ?? new byte[4], st.Ticket);
    }

    /// <summary>
    /// Finds the TGT (a <c>krbtgt/…</c> server) in a parsed ccache and reconstructs a <see cref="Tgt"/>
    /// — the ticket + session key the TGS examples and <c>-k</c> build on. Throws if none is present.
    /// </summary>
    public static Tgt ToTgt(CCacheFile ccache)
    {
        CcacheCredential c = ccache.Credentials.FirstOrDefault(c => c.ServerName.StartsWith("krbtgt/", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("ccache has no TGT (krbtgt/…) credential.");

        return new Tgt(c.Ticket, c.KeyType, c.Key, c.EndTime, c.ClientRealm, c.ClientName, c.ServerName,
            c.Flags, c.AuthTime, c.StartTime, c.RenewTill);
    }

    // --- principal encoding ----------------------------------------------------------------------

    private static void WritePrincipal(Stream s, int nameType, string nameWithComponents, string realm)
    {
        string[] components = nameWithComponents.Split('/');
        WriteU32(s, (uint)nameType);
        WriteU32(s, (uint)components.Length);
        WriteCountedOctetString(s, Encoding.UTF8.GetBytes(realm));
        foreach (string c in components)
        {
            WriteCountedOctetString(s, Encoding.UTF8.GetBytes(c));
        }
    }

    private static (string Name, string Realm) ReadPrincipal(byte[] data, ref int p)
    {
        p += 4;                                              // name_type
        int numComponents = (int)ReadU32(data, ref p);
        string realm = Encoding.UTF8.GetString(ReadCountedOctetString(data, ref p));
        var parts = new string[numComponents];
        for (int i = 0; i < numComponents; i++)
        {
            parts[i] = Encoding.UTF8.GetString(ReadCountedOctetString(data, ref p));
        }

        return (string.Join('/', parts), realm);
    }

    private static void SkipTaggedList(byte[] data, ref int p)
    {
        int count = (int)ReadU32(data, ref p);
        for (int i = 0; i < count; i++)
        {
            p += 2;                                          // addrtype / authtype
            int len = (int)ReadU32(data, ref p);
            p += len;
        }
    }

    // --- primitives ------------------------------------------------------------------------------

    private static byte[] FourByteFlags(byte[] flags)
    {
        var f = new byte[4];
        Array.Copy(flags, f, Math.Min(4, flags.Length));
        return f;
    }

    private static uint ToUnix(DateTimeOffset dt) => dt <= DateTimeOffset.UnixEpoch ? 0 : (uint)dt.ToUnixTimeSeconds();

    private static DateTimeOffset FromUnix(uint t) => DateTimeOffset.FromUnixTimeSeconds(t);

    private static void WriteU16(Stream s, ushort v)
    {
        Span<byte> b = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(b, v);
        s.Write(b);
    }

    private static void WriteU32(Stream s, uint v)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, v);
        s.Write(b);
    }

    private static void WriteCountedOctetString(Stream s, byte[] data)
    {
        WriteU32(s, (uint)data.Length);
        s.Write(data);
    }

    private static ushort ReadU16(byte[] d, ref int p)
    {
        ushort v = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(p));
        p += 2;
        return v;
    }

    private static uint ReadU32(byte[] d, ref int p)
    {
        uint v = BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(p));
        p += 4;
        return v;
    }

    private static byte[] ReadCountedOctetString(byte[] d, ref int p)
    {
        int len = (int)ReadU32(d, ref p);
        byte[] v = d[p..(p + len)];
        p += len;
        return v;
    }
}
