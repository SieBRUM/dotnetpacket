using System.Buffers.Binary;
using System.Text;

namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>One stored Kerberos key from supplementalCredentials: its etype, a readable name, and the key bytes.</summary>
public sealed record KerberosStoredKey(int KeyType, string KeyTypeName, byte[] Key);

/// <summary>
/// The parsed contents of a decrypted <c>supplementalCredentials</c> attribute (MS-SAMR USER_PROPERTIES):
/// the Kerberos keys (AES-256/AES-128/DES, from Primary:Kerberos-Newer-Keys) and, when present, the
/// stored cleartext password (Primary:CLEARTEXT). Ported from impacket's <c>samr</c> structures and the
/// supplemental-info path of <c>examples/secretsdump.py</c> (NTDSHashes.__decryptSupplementalInfo).
/// </summary>
/// <remarks>
/// DCSync returns Kerberos keys straight from the directory — reusable for pass-the-key / Silver/Golden
/// tickets without cracking — so surfacing them completes the secretsdump DRSUAPI output the SOC needs
/// to study. Decode-only and lab-first.
/// </remarks>
public sealed record SupplementalCredentials(IReadOnlyList<KerberosStoredKey> KerberosKeys, string? Cleartext)
{
    /// <summary>[MS-SAMR] 2.2.10.8 Kerberos etype → readable name (impacket's <c>KERBEROS_TYPE</c>).</summary>
    public static readonly IReadOnlyDictionary<int, string> KerberosTypeNames = new Dictionary<int, string>
    {
        [1] = "dec-cbc-crc",
        [3] = "des-cbc-md5",
        [17] = "aes128-cts-hmac-sha1-96",
        [18] = "aes256-cts-hmac-sha1-96",
        [unchecked((int)0xFFFFFF74)] = "rc4_hmac",
    };

    /// <summary>
    /// Parses a decrypted supplementalCredentials value (the raw USER_PROPERTIES blob). Returns the
    /// Kerberos-Newer-Keys and the cleartext password if those properties are present.
    /// </summary>
    public static SupplementalCredentials Parse(byte[] userProperties)
    {
        var keys = new List<KerberosStoredKey>();
        string? cleartext = null;

        // USER_PROPERTIES: fixed 0x6e-byte prefix (Reserved1..PropertySignature), then PropertyCount
        // at offset 110, the USER_PROPERTY entries, and a trailing Reserved5 byte.
        // propertiesEnd = 12 + Length. A header-only blob ends at the signature (PropertyCount omitted).
        const int propertyCountOffset = 110;
        if (userProperties.Length < propertyCountOffset + 2)
        {
            return new SupplementalCredentials(keys, cleartext);
        }

        uint length = BinaryPrimitives.ReadUInt32LittleEndian(userProperties.AsSpan(4));
        int propertiesEnd = 12 + (int)length;
        if (propertiesEnd <= propertyCountOffset || propertiesEnd > userProperties.Length)
        {
            return new SupplementalCredentials(keys, cleartext);
        }

        ushort propertyCount = BinaryPrimitives.ReadUInt16LittleEndian(userProperties.AsSpan(propertyCountOffset));
        int pos = propertyCountOffset + 2;

        for (int i = 0; i < propertyCount && pos + 6 <= propertiesEnd; i++)
        {
            ushort nameLen = BinaryPrimitives.ReadUInt16LittleEndian(userProperties.AsSpan(pos));
            ushort valueLen = BinaryPrimitives.ReadUInt16LittleEndian(userProperties.AsSpan(pos + 2));
            // userProperties[pos+4..pos+6] = Reserved
            int nameStart = pos + 6;
            int valueStart = nameStart + nameLen;
            if (valueStart + valueLen > userProperties.Length)
            {
                break;
            }

            string name = Encoding.Unicode.GetString(userProperties, nameStart, nameLen);
            // PropertyValue is stored as hex-ASCII text.
            byte[] valueHexAscii = userProperties[valueStart..(valueStart + valueLen)];
            pos = valueStart + valueLen;

            switch (name)
            {
                case "Primary:Kerberos-Newer-Keys":
                    keys.AddRange(ParseNewerKeys(FromHexAscii(valueHexAscii)));
                    break;
                case "Primary:CLEARTEXT":
                    cleartext = DecodeCleartext(FromHexAscii(valueHexAscii));
                    break;
            }
        }

        return new SupplementalCredentials(keys, cleartext);
    }

    private static List<KerberosStoredKey> ParseNewerKeys(byte[] blob)
    {
        var result = new List<KerberosStoredKey>();
        if (blob.Length < 24)
        {
            return result;
        }

        // KERB_STORED_CREDENTIAL_NEW header (24 bytes): Revision, Flags, CredentialCount, ...
        ushort credentialCount = BinaryPrimitives.ReadUInt16LittleEndian(blob.AsSpan(4));
        int keyData = 24; // Buffer starts after the fixed header
        for (int i = 0; i < credentialCount; i++)
        {
            // KERB_KEY_DATA_NEW (24 bytes): Reserved1/2/3, IterationCount, KeyType, KeyLength, KeyOffset.
            if (keyData + 24 > blob.Length)
            {
                break;
            }

            int keyType = BinaryPrimitives.ReadInt32LittleEndian(blob.AsSpan(keyData + 12));
            uint keyLength = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(keyData + 16));
            uint keyOffset = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(keyData + 20));
            keyData += 24;

            if (keyOffset + keyLength > (uint)blob.Length)
            {
                continue;
            }

            byte[] key = blob[(int)keyOffset..(int)(keyOffset + keyLength)];
            string typeName = KerberosTypeNames.TryGetValue(keyType, out string? n) ? n : $"0x{keyType:x}";
            result.Add(new KerberosStoredKey(keyType, typeName, key));
        }

        return result;
    }

    private static string DecodeCleartext(byte[] raw)
    {
        // Primary:CLEARTEXT is the UTF-16LE cleartext password; a machine password may not decode, so hex it.
        try
        {
            string s = Encoding.Unicode.GetString(raw);
            if (!s.Contains('�'))
            {
                return s;
            }
        }
        catch (ArgumentException)
        {
            // fall through to hex
        }

        return "0x" + Convert.ToHexString(raw).ToLowerInvariant();
    }

    private static byte[] FromHexAscii(byte[] hexAscii) =>
        Convert.FromHexString(Encoding.ASCII.GetString(hexAscii));
}
