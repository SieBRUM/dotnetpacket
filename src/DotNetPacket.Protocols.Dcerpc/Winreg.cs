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
    private const ushort OpnumBaseRegQueryValue = 17;
    private const ushort OpnumBaseRegGetVersion = 26;

    private const uint MaximumAllowed = 0x02000000;
    private const uint ErrorMoreData = 0x000000EA;

    /// <summary>A registry value read: its REG_* type, raw data, and the call's return code.</summary>
    public sealed record RegValue(uint Type, byte[] Data, uint ReturnCode)
    {
        public bool Success => ReturnCode == 0;

        /// <summary>The data as a string when the type is REG_SZ/EXPAND_SZ (1/2); otherwise a hex dump.</summary>
        public string AsText => Type is 1 or 2
            ? System.Text.Encoding.Unicode.GetString(Data).TrimEnd('\0')
            : Convert.ToHexString(Data);

        /// <summary>The REG_* type as a readable name (MS-RRP 2.2.9 / winnt.h).</summary>
        public string TypeName => Type switch
        {
            0 => "REG_NONE",
            1 => "REG_SZ",
            2 => "REG_EXPAND_SZ",
            3 => "REG_BINARY",
            4 => "REG_DWORD",
            7 => "REG_MULTI_SZ",
            11 => "REG_QWORD",
            _ => $"0x{Type:X}",
        };
    }

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

    /// <summary>
    /// BaseRegQueryValue (opnum 17): read a named value under an open key (the reg.py
    /// value read). Uses two-call sizing like reg.exe — a first call with a zero-length
    /// data buffer returns ERROR_MORE_DATA and the required size, then it re-queries with
    /// a buffer of that size (rather than impacket's fixed pre-allocation).
    /// </summary>
    public static RegValue QueryValue(DcerpcPipe pipe, byte[] hKey, string valueName)
    {
        // Start with a modest buffer; grow to the exact size if the server says so.
        (uint type, byte[] data, uint needed, uint ret) = QueryValueCall(pipe, hKey, valueName, 512);
        if (ret == ErrorMoreData && needed > 0)
        {
            (type, data, _, ret) = QueryValueCall(pipe, hKey, valueName, needed);
        }

        return new RegValue(type, data, ret);
    }

    private static (uint Type, byte[] Data, uint Needed, uint ReturnCode) QueryValueCall(
        DcerpcPipe pipe, byte[] hKey, string valueName, uint bufferSize)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(hKey);          // hKey [in]
        ndr.WriteRrpUnicodeString(valueName);  // lpValueName (NUL-counted RRP string)
        ndr.WriteReferent(true);               // lpType [in,out,unique]
        ndr.WriteUInt32(0);
        ndr.WriteReferent(true);               // lpData [in,out,unique] conformant-varying byte array
        ndr.WriteUInt32(bufferSize);           //   MaxCount
        ndr.WriteUInt32(0);                    //   Offset
        ndr.WriteUInt32(bufferSize);           //   ActualCount
        ndr.WriteBytes(new byte[bufferSize]);
        ndr.Align(4);
        ndr.WriteReferent(true);               // lpcbData [in,out,unique]
        ndr.WriteUInt32(bufferSize);
        ndr.WriteReferent(true);               // lpcbLen [in,out,unique]
        ndr.WriteUInt32(bufferSize);
        return ParseQueryValueResponse(pipe.Call(OpnumBaseRegQueryValue, ndr.ToArray()));
    }

    /// <summary>
    /// Parses a BaseRegQueryValue response: lpType, the lpData conformant-varying byte
    /// array, lpcbData (bytes needed/returned), lpcbLen, and the return code. Exposed
    /// for tests / offline analysis.
    /// </summary>
    public static (uint Type, byte[] Data, uint Needed, uint ReturnCode) ParseQueryValueResponse(byte[] stub)
    {
        var reader = new NdrReader(stub);
        uint type = reader.ReadReferent() != 0 ? reader.ReadUInt32() : 0;

        byte[] data = Array.Empty<byte>();
        if (reader.ReadReferent() != 0)
        {
            reader.ReadUInt32();                 // MaxCount
            reader.ReadUInt32();                 // Offset
            uint actual = reader.ReadUInt32();   // ActualCount
            data = reader.ReadBytes((int)actual);
            reader.Align(4);
        }

        uint needed = reader.ReadReferent() != 0 ? reader.ReadUInt32() : 0; // lpcbData (bytes needed/returned)
        if (reader.ReadReferent() != 0)
        {
            reader.ReadUInt32();                 // lpcbLen
        }

        uint returnCode = reader.ReadUInt32();
        return (type, data, needed, returnCode);
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
