using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Ldap;

/// <summary>
/// A single ACE (MS-DTYP 2.4.4) in a round-trippable form — the access-allowed/denied and their
/// object variants, which is all dacledit reads or writes. Port of impacket's <c>ldaptypes.ACE</c>
/// plus <c>ACCESS_ALLOWED_ACE</c> / <c>ACCESS_ALLOWED_OBJECT_ACE</c> (and the DENIED twins).
/// Serialization reproduces impacket's <c>getData()</c> exactly, including its AceSize recompute, so
/// a parsed-then-reserialized DACL matches what dacledit would push.
/// </summary>
public sealed class NtAce
{
    // ACE types (MS-DTYP 2.4.4.1 AceType).
    public const byte AccessAllowed = 0x00;
    public const byte AccessDenied = 0x01;
    public const byte AccessAllowedObject = 0x05;
    public const byte AccessDeniedObject = 0x06;

    // Object-ACE Flags (MS-DTYP 2.4.4.3).
    public const uint AceObjectTypePresent = 0x01;
    public const uint AceInheritedObjectTypePresent = 0x02;

    // ACE header AceFlags (MS-DTYP 2.4.4.1) used by -inheritance.
    public const byte ObjectInheritAce = 0x01;
    public const byte ContainerInheritAce = 0x02;

    // ADS rights used in object-ACE masks (MS-DTYP 2.4.4.3; ldaptypes.ACCESS_ALLOWED_OBJECT_ACE).
    public const uint AdsRightDsControlAccess = 0x00000100;
    public const uint AdsRightDsCreateChild = 0x00000001;
    public const uint AdsRightDsDeleteChild = 0x00000002;
    public const uint AdsRightDsReadProp = 0x00000010;
    public const uint AdsRightDsWriteProp = 0x00000020;
    public const uint AdsRightDsSelf = 0x00000008;

    public byte AceType { get; set; }

    public byte AceFlags { get; set; }

    public uint Mask { get; set; }

    /// <summary>Object-ACE Flags field (which GUIDs are present); only for the object ACE types.</summary>
    public uint ObjectFlags { get; set; }

    public Guid? ObjectType { get; set; }

    public Guid? InheritedObjectType { get; set; }

    /// <summary>Trustee SID in binary (MS-DTYP LDAP_SID, SubAuthority little-endian).</summary>
    public byte[] Sid { get; set; } = Array.Empty<byte>();

    public bool IsObjectAce => AceType is AccessAllowedObject or AccessDeniedObject;

    /// <summary>Reads one ACE from <paramref name="r"/>, positioned at the ACE header.</summary>
    public static NtAce Parse(ByteReader r)
    {
        int start = r.Position;
        var ace = new NtAce
        {
            AceType = r.ReadByte(),
            AceFlags = r.ReadByte(),
        };
        ushort aceSize = r.ReadUInt16();
        ace.Mask = r.ReadUInt32();

        if (ace.IsObjectAce)
        {
            ace.ObjectFlags = r.ReadUInt32();
            if ((ace.ObjectFlags & AceObjectTypePresent) != 0)
            {
                ace.ObjectType = new Guid(r.ReadBytes(16));
            }

            if ((ace.ObjectFlags & AceInheritedObjectTypePresent) != 0)
            {
                ace.InheritedObjectType = new Guid(r.ReadBytes(16));
            }
        }

        // The SID consumes exactly 8 + 4*SubAuthorityCount bytes; any trailing padding inside the
        // declared AceSize is dropped (impacket re-emits the SID minimally). SubAuthorityCount is the
        // second byte of the SID (after Revision).
        int sidStart = r.Position;
        r.ReadByte();                        // Revision
        int subAuthCount = r.ReadByte();     // SubAuthorityCount
        r.Position = sidStart;
        ace.Sid = r.ReadBytes(8 + (4 * subAuthCount));

        r.Position = start + aceSize; // skip any trailing pad to the next ACE
        return ace;
    }

    /// <summary>Serializes this ACE, matching impacket's <c>ACE.getData()</c> (AceSize recompute + pad).</summary>
    public byte[] Serialize()
    {
        var body = new ByteWriter(ByteOrder.Little);
        body.WriteUInt32(Mask);
        if (IsObjectAce)
        {
            uint flags = ObjectFlags;
            if (ObjectType is not null)
            {
                flags |= AceObjectTypePresent;
            }

            if (InheritedObjectType is not null)
            {
                flags |= AceInheritedObjectTypePresent;
            }

            body.WriteUInt32(flags);
            if (ObjectType is Guid ot)
            {
                body.WriteBytes(ot.ToByteArray());
            }

            if (InheritedObjectType is Guid it)
            {
                body.WriteBytes(it.ToByteArray());
            }
        }

        body.WriteBytes(Sid);
        byte[] bodyBytes = body.ToArray();

        int aceSize = bodyBytes.Length + 4; // 4-byte ACE header is included
        if (aceSize % 4 != 0)
        {
            aceSize += aceSize % 4; // reproduce impacket's (quirky) alignment exactly
        }

        var w = new ByteWriter(ByteOrder.Little);
        w.WriteByte(AceType);
        w.WriteByte(AceFlags);
        w.WriteUInt16((ushort)aceSize);
        w.WriteBytes(bodyBytes);
        byte[] data = w.ToArray();
        if (data.Length < aceSize)
        {
            Array.Resize(ref data, aceSize); // pad with zero bytes to the declared size
        }

        return data;
    }
}
