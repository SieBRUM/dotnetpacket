using System;
using System.Linq;
using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// DRSUAPI / DCSync (MS-DRSR) tests. The replication-secret cryptography is pinned by a
/// known-answer vector produced with impacket (<c>drsuapi.DecryptAttributeValue</c> +
/// <c>removeDESLayer</c>); the ATTRTYP conversion and request blobs are pinned byte-exact; and a
/// synthetic GetNCChanges reply is parsed and decrypted end-to-end to the known NT hash. The full
/// path is also validated live against the Samba AD DC lab (Administrator's NT hash matches the
/// known oracle ac8d0d3c9858659864b8493a51050efd — see docs/PORTING_STATUS.md).
/// </summary>
public class DrsuapiTests
{
    // impacket oracle (scratchpad/drs_oracle.py): sessionKey+salt+rid -> known NT hash.
    private static readonly byte[] SessionKey = Convert.FromHexString("0123456789abcdef0123456789abcdef");
    private const uint Rid = 500;
    private static readonly byte[] KnownNtHash = Convert.FromHexString("ac8d0d3c9858659864b8493a51050efd");

    // ENCRYPTED_PAYLOAD on the wire = Salt(16) || RC4(CheckSum(4) || DES-wrapped NT hash).
    private static readonly byte[] EncryptedPayload = Convert.FromHexString(
        "00112233445566778899aabbccddeeff31d496339da12f6416467607be28f5f375081fc7");

    [Fact]
    public void DecryptAttributeValue_ThenRemoveDesLayer_YieldsKnownNtHash()
    {
        byte[] inner = DrsCrypto.DecryptAttributeValue(SessionKey, EncryptedPayload); // outer RC4 layer
        byte[] ntHash = DrsCrypto.RemoveDesLayer(inner, Rid);                          // inner per-RID DES
        Assert.Equal(KnownNtHash, ntHash);
    }

    [Fact]
    public void DecryptAttributeValue_ChecksumVerifies()
    {
        // verifyChecksum defaults to true; a mismatch would throw. A flipped ciphertext byte must throw.
        byte[] ok = DrsCrypto.DecryptAttributeValue(SessionKey, EncryptedPayload);
        Assert.Equal(16, ok.Length);

        byte[] tampered = (byte[])EncryptedPayload.Clone();
        tampered[^1] ^= 0xFF;
        Assert.Throws<System.IO.InvalidDataException>(() => DrsCrypto.DecryptAttributeValue(SessionKey, tampered));
    }

    [Fact]
    public void Crc32_MatchesStandardCheckValue()
    {
        // The canonical CRC-32/ISO-HDLC check value for the ASCII string "123456789".
        Assert.Equal(0xCBF43926u, DrsCrypto.Crc32(System.Text.Encoding.ASCII.GetBytes("123456789")));
    }

    [Fact]
    public void DeriveKey_IsDeterministicSevenByteExpansion()
    {
        (byte[] k1, byte[] k2) = DrsCrypto.DeriveKey(Rid);
        Assert.Equal(8, k1.Length);
        Assert.Equal(8, k2.Length);
        // Same RID -> same keys (used to decrypt every hash of one account).
        (byte[] k1b, byte[] k2b) = DrsCrypto.DeriveKey(Rid);
        Assert.Equal(k1, k1b);
        Assert.Equal(k2, k2b);
    }

    [Fact]
    public void MakeAttid_ProducesImpacketAttids()
    {
        var table = new PrefixTable();
        Assert.Equal(0x5Au, table.MakeAttid("1.2.840.113556.1.4.90"));   // unicodePwd
        Assert.Equal(0x5Eu, table.MakeAttid("1.2.840.113556.1.4.94"));   // ntPwdHistory
        Assert.Equal(0xA0u, table.MakeAttid("1.2.840.113556.1.4.160"));  // lmPwdHistory
        Assert.Equal(0x290u, table.MakeAttid("1.2.840.113556.1.4.656")); // userPrincipalName (multi-byte arc)
        // All share the one MS prefix 1.2.840.113556.1.4, so only one entry is interned.
        Assert.Equal(1, table.Count);
    }

    [Fact]
    public void EncodeOidContents_MatchesBerPrefix()
    {
        // BER content octets of 1.2.840.113556.1.4.90 (impacket encode(...)[2:]).
        byte[] expected = Convert.FromHexString("2a864886f714010 45a".Replace(" ", string.Empty));
        Assert.Equal(expected, PrefixTable.EncodeOidContents("1.2.840.113556.1.4.90"));
    }

    [Fact]
    public void BuildExtensionsBlob_MatchesImpacketExceptDivergentPid()
    {
        // impacket DRS_EXTENSIONS_INT (scratchpad/drs_oracle.py DRSBIND_EXT_BLOB): dwFlags=0x05c08000,
        // NULL guids, dwReplEpoch/dwFlagsExt=0, dwExtCaps=0xffffffff (52 bytes). impacket hardcodes Pid=0;
        // DotNetPacket deliberately sends its real process id there (docs/WIRE_DIFF.md) — no real process
        // has PID 0, so a rule keying on "DRS_EXTENSIONS_INT with Pid=0" is an impacket/tool tell.
        byte[] impacket = Convert.FromHexString(
            "0080c0050000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffff");
        byte[] blob = Drsuapi.BuildExtensionsBlob();
        Assert.Equal(52, blob.Length);

        // Pid lives at offset 20 (after dwFlags(4) + SiteObjGuid(16)). It must be our real, non-zero PID…
        uint pid = BitConverter.ToUInt32(blob, 20);
        Assert.NotEqual(0u, pid);
        Assert.Equal((uint)Environment.ProcessId, pid);

        // …and every other byte must still match impacket's blob exactly (faithful protocol fields).
        byte[] normalized = (byte[])blob.Clone();
        Array.Clear(normalized, 20, 4); // zero the Pid field back to impacket's value
        Assert.Equal(impacket, normalized);
    }

    [Fact]
    public void BuildBindStub_DivergesFromImpacketNtdsapiClientGuid()
    {
        // Deliberate signature divergence (docs/WIRE_DIFF.md): the puuidClientDsa must be our per-run
        // DSA GUID, NOT impacket/mimikatz/ntdsapi's fixed e24d201a-4fd6-11d1-a3da-0000f875ae0d constant.
        byte[] stub = Drsuapi.BuildBindStub();
        Assert.True(SearchIndex(stub, Drsuapi.ClientDsaGuid.ToByteArray()) >= 0,
            "bind stub must carry our per-run client DSA GUID");
        Assert.True(SearchIndex(stub, Drsuapi.NtdsApiClientGuid.ToByteArray()) < 0,
            "bind stub must NOT carry impacket's fixed NTDSAPI client GUID (that is the tell we diverge from)");
        Assert.NotEqual(Drsuapi.NtdsApiClientGuid, Drsuapi.ClientDsaGuid);
    }

    [Fact]
    public void BuildGetNCChangesStub_CarriesTargetGuidAndLength()
    {
        var ntds = new Guid("c8b9d52f-cf64-4344-8afc-3e8861da6d77");
        var target = new Guid("4e4cbccd-106b-4eea-994f-30654acfd348");
        byte[] stub = Drsuapi.BuildGetNCChangesStub(new byte[20], ntds, target);

        // V8 EXOP_REPL_OBJ request with an empty prefix table (canonical attids; the interoperable
        // path the DC accepts — a custom prefix map makes Samba fail "decode remote prefixMap").
        Assert.Equal(264, stub.Length);
        // The target objectGUID appears in the pNC DSNAME (NDR little-endian GUID bytes).
        Assert.True(SearchIndex(stub, target.ToByteArray()) >= 0, "target GUID must be present in the DSNAME");
    }

    [Fact]
    public void ParseGetNCChangesReply_ParsesAndDecryptsSyntheticObject()
    {
        byte[] sid = BuildSid(Rid);
        byte[] reply = BuildSyntheticReply(
            dn: "CN=Administrator,CN=Users,DC=lab,DC=local",
            objectSid: sid,
            unicodePwdPayload: EncryptedPayload);

        DrsReplicaObject obj = Drsuapi.ParseGetNCChangesReply(reply);
        Assert.Equal("CN=Administrator,CN=Users,DC=lab,DC=local", obj.DistinguishedName);

        byte[]? sidVal = obj.FirstValue(Drsuapi.AttObjectSid);
        Assert.NotNull(sidVal);
        Assert.Equal(sid, sidVal);

        byte[]? enc = obj.FirstValue(Drsuapi.AttUnicodePwd);
        Assert.NotNull(enc);
        byte[] nt = DrsCrypto.RemoveDesLayer(DrsCrypto.DecryptAttributeValue(SessionKey, enc!), Rid);
        Assert.Equal(KnownNtHash, nt);
    }

    private static int SearchIndex(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i + needle.Length <= haystack.Length; i++)
        {
            if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle))
            {
                return i;
            }
        }

        return -1;
    }

    private static byte[] BuildSid(uint rid)
    {
        // S-1-5-21-1-2-3-<rid>, 28 bytes: rev(1) count(1) idauth(6) 5 subauths(20).
        var w = new List<byte> { 1, 5, 0, 0, 0, 0, 0, 5 };
        foreach (uint sub in new uint[] { 21, 1, 2, 3, rid })
        {
            w.AddRange(BitConverter.GetBytes(sub));
        }

        return w.ToArray();
    }

    /// <summary>
    /// Builds a minimal DRS_MSG_GETCHGREPLY_V6 (one object, two attributes) in the exact NDR layout
    /// the Samba DC emits (verified in scratchpad/walk.py), so the parser is exercised end-to-end.
    /// </summary>
    private static byte[] BuildSyntheticReply(string dn, byte[] objectSid, byte[] unicodePwdPayload)
    {
        var w = new NdrWriter();
        w.WriteUInt32(6);          // pdwOutVersion
        w.WriteUInt32(6);          // pmsgOut tag (V6)
        w.Align(8);
        w.WriteBytes(new byte[16]); // uuidDsaObjSrc
        w.WriteBytes(new byte[16]); // uuidInvocIdSrc
        w.WriteReferent(true);      // pNC
        w.Align(8);
        w.WriteBytes(new byte[24]); // usnvecFrom
        w.WriteBytes(new byte[24]); // usnvecTo
        w.WriteReferent(false);     // pUpToDateVecSrc = NULL
        w.WriteUInt32(0);           // PrefixTableSrc.PrefixCount
        w.WriteReferent(false);     // PrefixTableSrc.pPrefixEntry = NULL
        w.WriteUInt32(1);           // ulExtendedRet (EXOP_ERR_SUCCESS)
        w.WriteUInt32(1);           // cNumObjects
        w.WriteUInt32(0);           // cNumBytes
        w.WriteReferent(true);      // pObjects
        w.WriteUInt32(0);           // fMoreData
        w.WriteUInt32(0);           // cNumNcSizeObjectsc
        w.WriteUInt32(0);           // cNumNcSizeValues
        w.WriteUInt32(0);           // cNumValues
        w.WriteUInt32(0);           // rgValues
        w.WriteUInt32(0);           // dwDRSError

        // Deferred: pNC DSNAME (GUID-only).
        WriteGuidDsName(w);

        // pObjects REPLENTINFLIST.
        w.WriteReferent(false);     // pNextEntInf = NULL
        w.WriteReferent(true);      // Entinf.pName
        w.WriteUInt32(0);           // Entinf.ulFlags
        w.WriteUInt32(2);           // AttrBlock.attrCount
        w.WriteReferent(true);      // AttrBlock.pAttr
        w.WriteUInt32(0);           // fIsNCPrefix
        w.WriteReferent(false);     // pParentGuidm = NULL
        w.WriteReferent(false);     // pMetaDataExt = NULL

        // Deferred: pName DSNAME (with the DN), then the ATTR array.
        WriteNamedDsName(w, dn);

        w.WriteUInt32(2);           // ATTR array conformant max_count
        // ATTR[0] objectSid, ATTR[1] unicodePwd (inline parts first).
        w.WriteUInt32(Drsuapi.AttObjectSid);
        w.WriteUInt32(1);           // valCount
        w.WriteReferent(true);      // pAVal
        w.WriteUInt32(Drsuapi.AttUnicodePwd);
        w.WriteUInt32(1);           // valCount
        w.WriteReferent(true);      // pAVal

        // Deferred pAVal arrays, in order.
        WriteAttrValue(w, objectSid);
        WriteAttrValue(w, unicodePwdPayload);

        w.WriteUInt32(0);           // NDRCALL ErrorCode (trails all deferred data)
        return w.ToArray();
    }

    private static void WriteGuidDsName(NdrWriter w)
    {
        w.WriteUInt32(1);           // StringName max_count
        w.WriteUInt32(62);          // structLen
        w.WriteUInt32(0);           // SidLen
        w.WriteBytes(new byte[16]); // Guid
        w.WriteBytes(new byte[28]); // Sid
        w.WriteUInt32(0);           // NameLen
        w.WriteUInt16(0);           // StringName[0]
        w.Align(4);
    }

    private static void WriteNamedDsName(NdrWriter w, string dn)
    {
        string s = dn + "\0";
        w.WriteUInt32((uint)s.Length);  // StringName max_count
        w.WriteUInt32(0);               // structLen (unused by the parser)
        w.WriteUInt32(28);              // SidLen
        w.WriteBytes(new byte[16]);     // Guid
        w.WriteBytes(new byte[28]);     // Sid
        w.WriteUInt32((uint)s.Length);  // NameLen
        w.WriteBytes(System.Text.Encoding.Unicode.GetBytes(s));
        w.Align(4);
    }

    private static void WriteAttrValue(NdrWriter w, byte[] value)
    {
        w.WriteUInt32(1);                  // ATTRVAL array max_count
        w.WriteUInt32((uint)value.Length); // valLen
        w.WriteReferent(true);             // pVal
        w.WriteUInt32((uint)value.Length); // BYTE_ARRAY max_count
        w.WriteBytes(value);
        w.Align(4);
    }
}
