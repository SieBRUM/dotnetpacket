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
    private static readonly Asn1Tag SimplePasswordTag = new(TagClass.ContextSpecific, 0, isConstructed: false);
    private static readonly Asn1Tag ServerSaslCredsTag = new(TagClass.ContextSpecific, 7, isConstructed: false);
    private static readonly Asn1Tag SearchRequestTag = new(TagClass.Application, 3, isConstructed: true);
    private static readonly Asn1Tag SearchResultEntryTag = new(TagClass.Application, 4, isConstructed: true);
    private static readonly Asn1Tag SearchResultDoneTag = new(TagClass.Application, 5, isConstructed: true);
    private static readonly Asn1Tag SearchResultReferenceTag = new(TagClass.Application, 19, isConstructed: true);
    private static readonly Asn1Tag ModifyRequestTag = new(TagClass.Application, 6, isConstructed: true);
    private static readonly Asn1Tag AddRequestTag = new(TagClass.Application, 8, isConstructed: true);
    private static readonly Asn1Tag DelRequestTag = new(TagClass.Application, 10, isConstructed: false);
    private static readonly Asn1Tag ControlsTag = new(TagClass.ContextSpecific, 0, isConstructed: true);

    /// <summary>LDAP_SERVER_SD_FLAGS_OID (MS-ADTS): scope a security-descriptor read/write to given SD parts.</summary>
    public const string SdFlagsControlOid = "1.2.840.113556.1.4.801";

    /// <summary>SD flags (LDAP_SERVER_SD_FLAGS): which parts of the security descriptor a request touches.</summary>
    public const int SdFlagsOwner = 0x01;
    public const int SdFlagsGroup = 0x02;
    public const int SdFlagsDacl = 0x04;
    public const int SdFlagsSacl = 0x08;

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
    /// Relay target side (ntlmrelayx ldapattack): sends the victim's NTLM NEGOTIATE (Type 1) to the
    /// DC's LDAP as the first leg of a GSS-SPNEGO SASL bind and returns the DC's CHALLENGE (Type 2).
    /// The bind is deliberately unsigned (the relay holds no session key), which is exactly what LDAP
    /// signing / channel binding is meant to reject.
    /// </summary>
    public byte[] RelayBindChallenge(byte[] victimType1)
    {
        LdapBindResponse first = SaslBind(GssSpnego, Spnego.WrapInitialToken(victimType1));
        if (!first.SaslInProgress)
        {
            throw new InvalidOperationException(
                $"DC did not continue the SASL bind (result {first.ResultCode}: {first.DiagnosticMessage}).");
        }

        return Spnego.ExtractResponseToken(first.ServerSaslCreds); // the DC's Type 2
    }

    /// <summary>
    /// Relay target side (ntlmrelayx ldapattack): forwards the victim's NTLM AUTHENTICATE (Type 3) and
    /// optional mechListMIC to the DC's LDAP as the second SASL-bind leg, and returns the LDAP result
    /// code (0 = bind succeeded, i.e. the relay is now authenticated as the victim).
    /// </summary>
    public int RelayBindAuthenticate(byte[] victimType3, byte[]? mechListMic)
    {
        LdapBindResponse final = SaslBind(GssSpnego, Spnego.WrapResponseToken(victimType3, mechListMic));
        return final.ResultCode;
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

    /// <summary>
    /// Performs an LDAP simple bind (RFC 4511 4.2): name (a DN or UPN) + password in the
    /// <c>simple [0]</c> CHOICE. The password crosses the wire in cleartext, so a real
    /// deployment does this only under TLS; the lab allows it on plaintext 389 for validation
    /// (see docs). Returns the parsed BindResponse (ResultCode 0 = success).
    /// </summary>
    public LdapBindResponse SimpleBind(string name, string password)
    {
        int id = ++_messageId;
        var writer = new AsnWriter(AsnEncodingRules.BER);
        using (writer.PushSequence())                       // LDAPMessage
        {
            writer.WriteInteger(id);                         // messageID
            using (writer.PushSequence(BindRequestTag))     // BindRequest [APPLICATION 0]
            {
                writer.WriteInteger(3);                      // version
                writer.WriteOctetString(Encoding.UTF8.GetBytes(name)); // name (LDAPDN / UPN)
                writer.WriteOctetString(Encoding.UTF8.GetBytes(password), SimplePasswordTag); // simple [0]
            }
        }

        _stream.Write(writer.Encode());
        return ParseBindResponse(ReadMessage());
    }

    /// <summary>
    /// LDAP AddRequest (RFC 4511 4.7): create <paramref name="dn"/> with <paramref name="attributes"/>
    /// (each a type plus one or more raw values). Returns the LDAPResult.
    /// </summary>
    public LdapResult Add(string dn, IReadOnlyList<(string Type, IReadOnlyList<byte[]> Values)> attributes)
    {
        _stream.Write(EncodeAddRequest(++_messageId, dn, attributes));
        return ParseLdapResult(ReadMessage(), new Asn1Tag(TagClass.Application, 9, isConstructed: true)); // AddResponse
    }

    /// <summary>LDAP DelRequest (RFC 4511 4.8): delete <paramref name="dn"/>. Returns the LDAPResult.</summary>
    public LdapResult Delete(string dn)
    {
        int id = ++_messageId;
        var w = new AsnWriter(AsnEncodingRules.BER);
        using (w.PushSequence())
        {
            w.WriteInteger(id);
            w.WriteOctetString(Encoding.UTF8.GetBytes(dn), DelRequestTag); // DelRequest [APPLICATION 10] primitive
        }

        _stream.Write(w.Encode());
        return ParseLdapResult(ReadMessage(), new Asn1Tag(TagClass.Application, 11, isConstructed: true)); // DelResponse
    }

    /// <summary>
    /// LDAP ModifyRequest (RFC 4511 4.6) with a single replace of <paramref name="attribute"/> to
    /// <paramref name="values"/>. Returns the LDAPResult.
    /// </summary>
    public LdapResult ModifyReplace(string dn, string attribute, IReadOnlyList<byte[]> values, int sdFlags = 0)
    {
        _stream.Write(EncodeModifyReplace(++_messageId, dn, attribute, values, sdFlags));
        return ParseLdapResult(ReadMessage(), new Asn1Tag(TagClass.Application, 7, isConstructed: true)); // ModifyResponse
    }

    /// <summary>
    /// Encodes a ModifyRequest LDAPMessage replacing <paramref name="attribute"/> (exposed for tests).
    /// When <paramref name="sdFlags"/> is non-zero an LDAP_SERVER_SD_FLAGS control is attached, as
    /// dacledit does (sdflags=0x04) to replace only the DACL of nTSecurityDescriptor.
    /// </summary>
    public static byte[] EncodeModifyReplace(int messageId, string dn, string attribute, IReadOnlyList<byte[]> values, int sdFlags = 0)
    {
        var w = new AsnWriter(AsnEncodingRules.BER);
        using (w.PushSequence())
        {
            w.WriteInteger(messageId);
            using (w.PushSequence(ModifyRequestTag))     // ModifyRequest [APPLICATION 6]
            {
                w.WriteOctetString(Encoding.UTF8.GetBytes(dn)); // object
                using (w.PushSequence())                 // changes SEQUENCE OF
                using (w.PushSequence())                 // change
                {
                    w.WriteEnumeratedValue(LdapModifyOp.Replace); // operation
                    using (w.PushSequence())             // modification PartialAttribute
                    {
                        w.WriteOctetString(Encoding.UTF8.GetBytes(attribute));
                        using (w.PushSetOf())
                        {
                            foreach (byte[] v in values)
                            {
                                w.WriteOctetString(v);
                            }
                        }
                    }
                }
            }

            WriteSdFlagsControls(w, sdFlags);
        }

        return w.Encode();
    }

    /// <summary>Encodes an AddRequest LDAPMessage (exposed for tests / offline analysis).</summary>
    public static byte[] EncodeAddRequest(int messageId, string dn, IReadOnlyList<(string Type, IReadOnlyList<byte[]> Values)> attributes)
    {
        var w = new AsnWriter(AsnEncodingRules.BER);
        using (w.PushSequence())                         // LDAPMessage
        {
            w.WriteInteger(messageId);
            using (w.PushSequence(AddRequestTag))        // AddRequest [APPLICATION 8]
            {
                w.WriteOctetString(Encoding.UTF8.GetBytes(dn)); // entry
                using (w.PushSequence())                 // attributes SEQUENCE OF
                {
                    foreach ((string type, IReadOnlyList<byte[]> values) in attributes)
                    {
                        using (w.PushSequence())         // attribute
                        {
                            w.WriteOctetString(Encoding.UTF8.GetBytes(type));
                            using (w.PushSetOf())        // vals SET OF
                            {
                                foreach (byte[] v in values)
                                {
                                    w.WriteOctetString(v);
                                }
                            }
                        }
                    }
                }
            }
        }

        return w.Encode();
    }

    // Parses an LDAPResult-bearing response (AddResponse/ModifyResponse/DelResponse share the shape).
    private static LdapResult ParseLdapResult(byte[] message, Asn1Tag responseTag)
    {
        var top = new AsnReader(message, AsnEncodingRules.BER);
        AsnReader ldapMessage = top.ReadSequence();
        ldapMessage.ReadInteger();                       // messageID
        AsnReader op = ldapMessage.ReadSequence(responseTag);

        int code = 0;
        foreach (byte b in op.ReadEnumeratedBytes().Span) // resultCode ENUMERATED
        {
            code = (code << 8) | b;
        }

        op.ReadOctetString();                            // matchedDN
        string diag = Encoding.UTF8.GetString(op.ReadOctetString()); // diagnosticMessage
        return new LdapResult(code, diag);
    }

    /// <summary>
    /// Runs an LDAP search (RFC 4511 4.5) and returns every SearchResultEntry. Reads messages
    /// until the SearchResultDone. Referrals/continuations are skipped. This is an unpaged
    /// search (sizeLimit as given); the ported examples target a small lab directory, so paged
    /// results (SimplePagedResultsControl) are not implemented — noted in PORTING_STATUS.
    /// </summary>
    public IReadOnlyList<SearchEntry> Search(
        string baseObject,
        LdapFilter filter,
        IReadOnlyList<string> attributes,
        LdapSearchScope scope = LdapSearchScope.WholeSubtree,
        int sizeLimit = 0,
        int timeLimit = 0,
        int sdFlags = 0)
    {
        int id = ++_messageId;
        _stream.Write(EncodeSearchRequest(id, baseObject, filter, attributes, scope, sizeLimit, timeLimit, sdFlags));

        var entries = new List<SearchEntry>();
        while (true)
        {
            var top = new AsnReader(ReadMessage(), AsnEncodingRules.BER);
            AsnReader message = top.ReadSequence();
            message.ReadInteger();                           // messageID
            Asn1Tag tag = message.PeekTag();

            if (tag.HasSameClassAndValue(SearchResultEntryTag))
            {
                entries.Add(ParseSearchEntry(message.ReadSequence(SearchResultEntryTag)));
            }
            else if (tag.HasSameClassAndValue(SearchResultDoneTag))
            {
                break; // the search is complete (result code ignored here)
            }
            else
            {
                message.ReadEncodedValue(); // SearchResultReference or anything else — skip
            }
        }

        return entries;
    }

    /// <summary>
    /// Encodes a SearchRequest LDAPMessage (RFC 4511 4.5.1) to its BER bytes (exposed for
    /// tests / offline analysis). Deterministic for a given message id and search.
    /// </summary>
    public static byte[] EncodeSearchRequest(
        int messageId,
        string baseObject,
        LdapFilter filter,
        IReadOnlyList<string> attributes,
        LdapSearchScope scope = LdapSearchScope.WholeSubtree,
        int sizeLimit = 0,
        int timeLimit = 0,
        int sdFlags = 0)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);
        using (writer.PushSequence())                       // LDAPMessage
        {
            writer.WriteInteger(messageId);                  // messageID
            using (writer.PushSequence(SearchRequestTag))   // SearchRequest [APPLICATION 3]
            {
                writer.WriteOctetString(Encoding.UTF8.GetBytes(baseObject)); // baseObject
                writer.WriteEnumeratedValue(scope);                          // scope
                writer.WriteEnumeratedValue(LdapDerefAliases.NeverDerefAliases); // derefAliases
                writer.WriteInteger(sizeLimit);              // sizeLimit
                writer.WriteInteger(timeLimit);              // timeLimit
                writer.WriteBoolean(false);                  // typesOnly
                filter.Write(writer);                        // filter
                using (writer.PushSequence())                // attributes (SEQUENCE OF LDAPString)
                {
                    foreach (string attr in attributes)
                    {
                        writer.WriteOctetString(Encoding.UTF8.GetBytes(attr));
                    }
                }
            }

            WriteSdFlagsControls(writer, sdFlags);
        }

        return writer.Encode();
    }

    /// <summary>
    /// Writes the LDAPMessage-level <c>controls [0]</c> carrying a single LDAP_SERVER_SD_FLAGS control
    /// (OID 1.2.840.113556.1.4.801) when <paramref name="sdFlags"/> is non-zero. criticality is left
    /// at its default (FALSE, hence omitted), matching ldap3's <c>security_descriptor_control</c> which
    /// dacledit uses. No-op when sdFlags == 0. Must be called inside the LDAPMessage SEQUENCE, after
    /// the protocolOp.
    /// </summary>
    private static void WriteSdFlagsControls(AsnWriter w, int sdFlags)
    {
        if (sdFlags == 0)
        {
            return;
        }

        using (w.PushSequence(ControlsTag))               // controls [0] Controls
        using (w.PushSequence())                          // Control
        {
            w.WriteOctetString(Encoding.ASCII.GetBytes(SdFlagsControlOid)); // controlType (LDAPOID)
            w.WriteOctetString(EncodeSdFlagsControlValue(sdFlags));         // controlValue (OCTET STRING)
        }
    }

    /// <summary>
    /// Encodes the LDAP_SERVER_SD_FLAGS controlValue: BER of SEQUENCE { INTEGER sdflags } (e.g. 0x04
    /// -&gt; 30 03 02 01 04). Exposed for tests / offline analysis.
    /// </summary>
    public static byte[] EncodeSdFlagsControlValue(int sdFlags)
    {
        var cv = new AsnWriter(AsnEncodingRules.BER);
        using (cv.PushSequence())
        {
            cv.WriteInteger(sdFlags);
        }

        return cv.Encode();
    }

    /// <summary>Parses a SearchResultEntry LDAPMessage (exposed for tests / offline analysis).</summary>
    public static SearchEntry ParseSearchEntry(byte[] message)
    {
        var top = new AsnReader(message, AsnEncodingRules.BER);
        AsnReader ldapMessage = top.ReadSequence();
        ldapMessage.ReadInteger();                           // messageID
        return ParseSearchEntry(ldapMessage.ReadSequence(SearchResultEntryTag));
    }

    private static SearchEntry ParseSearchEntry(AsnReader entry)
    {
        string objectName = Encoding.UTF8.GetString(entry.ReadOctetString()); // objectName LDAPDN

        var attributes = new List<SearchAttribute>();
        AsnReader attrList = entry.ReadSequence();           // PartialAttributeList
        while (attrList.HasData)
        {
            AsnReader attr = attrList.ReadSequence();
            string type = Encoding.UTF8.GetString(attr.ReadOctetString()); // type
            var values = new List<byte[]>();
            AsnReader vals = attr.ReadSetOf();               // vals SET OF AttributeValue
            while (vals.HasData)
            {
                values.Add(vals.ReadOctetString());
            }

            attributes.Add(new SearchAttribute(type, values));
        }

        return new SearchEntry(objectName, attributes);
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
