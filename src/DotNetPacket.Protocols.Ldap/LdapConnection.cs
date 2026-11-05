using System.Formats.Asn1;
using System.Net.Sockets;
using System.Text;
using DotNetPacket.Protocols.Ntlm;

namespace DotNetPacket.Protocols.Ldap;

/// <summary>Parsed LDAP BindResponse (RFC 4511 4.2.2): result code, diagnostic, and optional server SASL creds.</summary>
public sealed record LdapBindResponse(int ResultCode, string DiagnosticMessage, byte[] ServerSaslCreds)
{
    public bool Success => ResultCode == LdapResultCode.Success;
    public bool SaslInProgress => ResultCode == LdapResultCode.SaslBindInProgress;
    public bool StrongerAuthRequired => ResultCode == LdapResultCode.StrongerAuthRequired;
}

/// <summary>
/// Minimal LDAP (RFC 4511) client over TCP — the bind path only. Port of the parts of
/// impacket's <c>impacket.ldap.ldap.LDAPConnection</c> used by <c>CheckLDAPStatus.py</c>:
/// a GSS-SPNEGO (NTLM) SASL bind, used to probe whether a DC requires LDAP signing.
/// LDAP PDUs are BER-encoded LDAPMessage structures framed directly on the TCP stream
/// (no extra length prefix). Reuses the existing NTLM / SPNEGO stack for the SASL creds.
/// </summary>
public sealed class LdapConnection : IDisposable
{
    private static readonly Asn1Tag BindRequestTag = new(TagClass.Application, 0, isConstructed: true);
    private static readonly Asn1Tag BindResponseTag = new(TagClass.Application, 1, isConstructed: true);
    private static readonly Asn1Tag SaslCredentialsTag = new(TagClass.ContextSpecific, 3, isConstructed: true);
    private static readonly Asn1Tag ServerSaslCredsTag = new(TagClass.ContextSpecific, 7, isConstructed: false);

    private const string GssSpnego = "GSS-SPNEGO";

    private readonly TcpClient _tcp;
    private readonly NetworkStream _stream;
    private int _messageId;

    private LdapConnection(TcpClient tcp)
    {
        _tcp = tcp;
        _stream = tcp.GetStream();
    }

    /// <summary>Opens a plaintext LDAP connection to <paramref name="host"/>:<paramref name="port"/> (default 389).</summary>
    public static LdapConnection Connect(string host, int port = 389)
    {
        var tcp = new TcpClient();
        tcp.Connect(host, port);
        return new LdapConnection(tcp);
    }

    /// <summary>
    /// Runs the <c>CheckLDAPStatus</c> signing probe: an unsigned GSS-SPNEGO NTLM bind.
    /// If the DC requires LDAP signing it answers the final bind with
    /// <c>strongerAuthRequired</c> (result 8); otherwise the bind proceeds past it. The probe
    /// needs no valid credentials — the server enforces signing before it checks the password —
    /// so (like impacket) it binds with an empty user/password.
    /// </summary>
    public LdapBindResponse NtlmSigningProbe(string domain)
    {
        // Match impacket's GSS-SPNEGO signing probe: negotiate SEAL + KEY_EXCH (flags 0xe2888235)
        // and send an ANONYMOUS NTLM AUTHENTICATE (empty NT response). A signing-required DC
        // answers that bind with strongerAuthRequired before it would validate any credentials.
        var ntlm = new NtlmClient { KeyExchange = true };
        byte[] negotiate = ntlm.CreateNegotiate();                    // NTLM Type 1
        LdapBindResponse first = SaslBind(GssSpnego, Spnego.WrapInitialToken(negotiate));
        if (!first.SaslInProgress)
        {
            return first; // server refused the first leg outright
        }

        Spnego.ExtractResponseToken(first.ServerSaslCreds);           // NTLM Type 2 (challenge, unused for anon)
        byte[] authenticate = ntlm.CreateAnonymousAuthenticate(domain); // anonymous NTLM Type 3
        return SaslBind(GssSpnego, Spnego.WrapResponseToken(authenticate)); // NTLM Type 3
    }

    /// <summary>Sends one SASL BindRequest (RFC 4511 4.2) and returns the parsed BindResponse.</summary>
    public LdapBindResponse SaslBind(string mechanism, byte[] credentials)
    {
        int id = ++_messageId;
        var writer = new AsnWriter(AsnEncodingRules.BER);
        using (writer.PushSequence())                       // LDAPMessage
        {
            writer.WriteInteger(id);                         // messageID
            using (writer.PushSequence(BindRequestTag))     // BindRequest [APPLICATION 0]
            {
                writer.WriteInteger(3);                      // version
                writer.WriteOctetString(ReadOnlySpan<byte>.Empty); // name (LDAPDN "")
                using (writer.PushSequence(SaslCredentialsTag)) // authentication CHOICE sasl [3]
                {
                    writer.WriteOctetString(Encoding.ASCII.GetBytes(mechanism)); // mechanism
                    writer.WriteOctetString(credentials);    // credentials
                }
            }
        }

        _stream.Write(writer.Encode());
        return ParseBindResponse(ReadMessage());
    }

    /// <summary>
    /// Parses an LDAPMessage carrying a BindResponse (exposed for tests / offline analysis).
    /// </summary>
    public static LdapBindResponse ParseBindResponse(byte[] message)
    {
        var top = new AsnReader(message, AsnEncodingRules.BER);
        AsnReader ldapMessage = top.ReadSequence();
        ldapMessage.ReadInteger();                          // messageID
        AsnReader bind = ldapMessage.ReadSequence(BindResponseTag);

        int resultCode = 0;
        foreach (byte b in bind.ReadEnumeratedBytes().Span) // resultCode ENUMERATED
        {
            resultCode = (resultCode << 8) | b;
        }

        bind.ReadOctetString();                              // matchedDN (LDAPDN, ignored)
        string diagnostic = Encoding.UTF8.GetString(bind.ReadOctetString()); // diagnosticMessage (LDAPString)

        byte[] serverSaslCreds = Array.Empty<byte>();
        while (bind.HasData)
        {
            Asn1Tag tag = bind.PeekTag();
            if (tag.HasSameClassAndValue(ServerSaslCredsTag))
            {
                serverSaslCreds = bind.ReadOctetString(ServerSaslCredsTag);
            }
            else
            {
                bind.ReadEncodedValue(); // referral [3] or anything else we don't need
            }
        }

        return new LdapBindResponse(resultCode, diagnostic, serverSaslCreds);
    }

    /// <summary>Reads one complete BER-framed LDAPMessage (tag + length + content) off the stream.</summary>
    private byte[] ReadMessage()
    {
        int tag = ReadByteOrThrow();
        int first = ReadByteOrThrow();

        var header = new List<byte> { (byte)tag, (byte)first };
        int contentLength;
        if (first < 0x80)
        {
            contentLength = first;              // short-form length
        }
        else
        {
            int lengthBytes = first & 0x7F;     // long-form: this many length octets follow
            contentLength = 0;
            for (int i = 0; i < lengthBytes; i++)
            {
                int b = ReadByteOrThrow();
                header.Add((byte)b);
                contentLength = (contentLength << 8) | b;
            }
        }

        var content = new byte[contentLength];
        int read = 0;
        while (read < contentLength)
        {
            int n = _stream.Read(content, read, contentLength - read);
            if (n <= 0)
            {
                throw new EndOfStreamException("LDAP connection closed mid-message.");
            }

            read += n;
        }

        var message = new byte[header.Count + contentLength];
        header.CopyTo(message);
        Array.Copy(content, 0, message, header.Count, contentLength);
        return message;
    }

    private int ReadByteOrThrow()
    {
        int b = _stream.ReadByte();
        if (b < 0)
        {
            throw new EndOfStreamException("LDAP connection closed.");
        }

        return b;
    }

    public void Dispose()
    {
        _stream.Dispose();
        _tcp.Dispose();
    }
}
