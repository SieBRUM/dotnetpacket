using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// supplementalCredentials (MS-SAMR USER_PROPERTIES) parse tests. A synthetic blob with a
/// Primary:Kerberos-Newer-Keys property (AES-256 + DES) and a Primary:CLEARTEXT property is built in
/// the exact [MS-SAMR] layout and parsed back. The real DCSync path is validated live against the lab
/// (Administrator's AES-256/AES-128 keys match the keys derived from the known password + salt — see
/// docs/PORTING_STATUS.md).
/// </summary>
public class SupplementalCredentialsTests
{
    private static readonly byte[] Aes256Key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] DesKey = Enumerable.Range(100, 8).Select(i => (byte)i).ToArray();
    private const string Cleartext = "Lab Passw0rd!";

    [Fact]
    public void Parse_ExtractsKerberosKeysAndCleartext()
    {
        byte[] blob = BuildUserProperties();
        SupplementalCredentials creds = SupplementalCredentials.Parse(blob);

        Assert.Equal(2, creds.KerberosKeys.Count);
        KerberosStoredKey aes = creds.KerberosKeys[0];
        Assert.Equal(18, aes.KeyType);
        Assert.Equal("aes256-cts-hmac-sha1-96", aes.KeyTypeName);
        Assert.Equal(Aes256Key, aes.Key);

        KerberosStoredKey des = creds.KerberosKeys[1];
        Assert.Equal(3, des.KeyType);
        Assert.Equal("des-cbc-md5", des.KeyTypeName);
        Assert.Equal(DesKey, des.Key);

        Assert.Equal(Cleartext, creds.Cleartext);
    }

    [Fact]
    public void Parse_HeaderOnlyBlob_ReturnsEmpty()
    {
        // A USER_PROPERTIES with Length pointing at the signature (no entries) must not throw.
        var w = new List<byte>();
        w.AddRange(new byte[4]);                 // Reserved1
        w.AddRange(BitConverter.GetBytes(98u));  // Length = 110 - 12 (ends at signature)
        w.AddRange(new byte[4]);                 // Reserved2/3
        w.AddRange(new byte[96]);                // Reserved4
        w.AddRange(BitConverter.GetBytes((ushort)0x50)); // PropertySignature
        w.Add(0);                                // Reserved5

        SupplementalCredentials creds = SupplementalCredentials.Parse(w.ToArray());
        Assert.Empty(creds.KerberosKeys);
        Assert.Null(creds.Cleartext);
    }

    private static byte[] BuildUserProperties()
    {
        byte[] kerbProp = BuildKerberosNewerKeys();
        byte[] clearProp = Encoding.Unicode.GetBytes(Cleartext);

        var entries = new List<byte>();
        AppendProperty(entries, "Primary:Kerberos-Newer-Keys", kerbProp);
        AppendProperty(entries, "Primary:CLEARTEXT", clearProp);

        var w = new List<byte>();
        w.AddRange(new byte[4]);                                   // Reserved1
        w.AddRange(BitConverter.GetBytes((uint)(100 + entries.Count))); // Length = (112 - 12) + entries
        w.AddRange(new byte[4]);                                   // Reserved2 + Reserved3
        w.AddRange(new byte[96]);                                  // Reserved4
        w.AddRange(BitConverter.GetBytes((ushort)0x50));          // PropertySignature
        w.AddRange(BitConverter.GetBytes((ushort)2));             // PropertyCount
        w.AddRange(entries);                                       // USER_PROPERTY entries
        w.Add(0);                                                  // Reserved5
        return w.ToArray();
    }

    // A USER_PROPERTY stores its value as hex-ASCII text.
    private static void AppendProperty(List<byte> dst, string name, byte[] value)
    {
        byte[] nameBytes = Encoding.Unicode.GetBytes(name);
        byte[] valueHex = Encoding.ASCII.GetBytes(Convert.ToHexString(value).ToLowerInvariant());
        dst.AddRange(BitConverter.GetBytes((ushort)nameBytes.Length));
        dst.AddRange(BitConverter.GetBytes((ushort)valueHex.Length));
        dst.AddRange(BitConverter.GetBytes((ushort)0)); // Reserved
        dst.AddRange(nameBytes);
        dst.AddRange(valueHex);
    }

    // KERB_STORED_CREDENTIAL_NEW: 24-byte header + two KERB_KEY_DATA_NEW + the key bytes.
    private static byte[] BuildKerberosNewerKeys()
    {
        const int headerLen = 24;
        const int keyDataLen = 24;
        int firstKeyOffset = headerLen + 2 * keyDataLen;

        var w = new List<byte>();
        w.AddRange(BitConverter.GetBytes((ushort)4));  // Revision
        w.AddRange(BitConverter.GetBytes((ushort)0));  // Flags
        w.AddRange(BitConverter.GetBytes((ushort)2));  // CredentialCount
        w.AddRange(BitConverter.GetBytes((ushort)0));  // ServiceCredentialCount
        w.AddRange(BitConverter.GetBytes((ushort)0));  // OldCredentialCount
        w.AddRange(BitConverter.GetBytes((ushort)0));  // OlderCredentialCount
        w.AddRange(BitConverter.GetBytes((ushort)0));  // DefaultSaltLength
        w.AddRange(BitConverter.GetBytes((ushort)0));  // DefaultSaltMaximumLength
        w.AddRange(BitConverter.GetBytes(0u));         // DefaultSaltOffset
        w.AddRange(BitConverter.GetBytes(4096u));      // DefaultIterationCount

        AppendKeyData(w, keyType: 18, Aes256Key.Length, firstKeyOffset);
        AppendKeyData(w, keyType: 3, DesKey.Length, firstKeyOffset + Aes256Key.Length);
        w.AddRange(Aes256Key);
        w.AddRange(DesKey);
        return w.ToArray();
    }

    private static void AppendKeyData(List<byte> w, int keyType, int keyLength, int keyOffset)
    {
        w.AddRange(BitConverter.GetBytes((ushort)0)); // Reserved1
        w.AddRange(BitConverter.GetBytes((ushort)0)); // Reserved2
        w.AddRange(BitConverter.GetBytes(0u));        // Reserved3
        w.AddRange(BitConverter.GetBytes(4096u));     // IterationCount
        w.AddRange(BitConverter.GetBytes(keyType));   // KeyType
        w.AddRange(BitConverter.GetBytes(keyLength)); // KeyLength
        w.AddRange(BitConverter.GetBytes(keyOffset)); // KeyOffset
    }
}
