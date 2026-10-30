namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>
/// Minimal winreg / Remote Registry client (MS-RRP). Port of the share of
/// impacket's <c>dcerpc.v5.rrp</c> used by <c>reg.py</c> recon: connect to the
/// remote HKLM hive, read its version, and open a key. The pipe must already be
/// bound to the winreg interface. Byte layout verified against impacket.
/// </summary>
/// <remarks>
/// Scoped to the calls this lab's Samba implements cleanly. BaseRegEnumKey /
/// BaseRegQueryInfoKey use impacket's pre-allocated-buffer scheme and/or are
/// unimplemented by standalone Samba; they are tracked in PORTING_STATUS.
/// </remarks>
public static class Winreg
{
    private const ushort OpnumOpenLocalMachine = 2;   // OpenHKLM
    private const ushort OpnumBaseRegCloseKey = 5;
    private const ushort OpnumBaseRegOpenKey = 15;
    private const ushort OpnumBaseRegGetVersion = 26;

    private const uint MaximumAllowed = 0x02000000;

    /// <summary>OpenLocalMachine / OpenHKLM (opnum 2): open the remote HKEY_LOCAL_MACHINE hive.</summary>
    public static ScHandleResult OpenHklm(DcerpcPipe pipe, uint desiredAccess = MaximumAllowed)
    {
        var ndr = new NdrWriter();
        ndr.WriteReferent(false);        // ServerName (unique ptr to USHORT, NULL)
        ndr.WriteUInt32(desiredAccess);  // samDesired
        byte[] stub = pipe.Call(OpnumOpenLocalMachine, ndr.ToArray());

        var reader = new NdrReader(stub);
        byte[] handle = reader.ReadContextHandle();
        return new ScHandleResult(handle, reader.ReadUInt32());
    }

    /// <summary>BaseRegGetVersion (opnum 26): the registry interface version of the key's hive.</summary>
    public static (uint Version, uint ReturnCode) GetVersion(DcerpcPipe pipe, byte[] hKey)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(hKey);
        byte[] stub = pipe.Call(OpnumBaseRegGetVersion, ndr.ToArray());

        var reader = new NdrReader(stub);
        uint version = reader.ReadUInt32();
        uint status = reader.ReadUInt32();
        return (version, status);
    }

    /// <summary>BaseRegOpenKey (opnum 15): open a subkey by name and get a key handle.</summary>
    public static ScHandleResult OpenKey(DcerpcPipe pipe, byte[] hKey, string subKey, uint desiredAccess = MaximumAllowed)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(hKey);
        ndr.WriteRrpUnicodeString(subKey);
        ndr.WriteUInt32(0);              // dwOptions = REG_OPTION_NON_VOLATILE (what Windows sends)
        ndr.WriteUInt32(desiredAccess);  // samDesired
        byte[] stub = pipe.Call(OpnumBaseRegOpenKey, ndr.ToArray());

        var reader = new NdrReader(stub);
        byte[] handle = reader.ReadContextHandle();
        return new ScHandleResult(handle, reader.ReadUInt32());
    }

    /// <summary>BaseRegCloseKey (opnum 5): release a key handle.</summary>
    public static uint CloseKey(DcerpcPipe pipe, byte[] hKey)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(hKey);
        byte[] stub = pipe.Call(OpnumBaseRegCloseKey, ndr.ToArray());

        var reader = new NdrReader(stub);
        reader.ReadContextHandle();
        return reader.ReadUInt32();
    }
}
