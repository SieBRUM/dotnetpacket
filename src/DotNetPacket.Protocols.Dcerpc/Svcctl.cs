namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>Service Control Manager / service access rights (MS-SCMR 2.2.1 / 3.1.4).</summary>
[Flags]
public enum ScManagerAccess : uint
{
    Connect = 0x0001,
    CreateService = 0x0002,
    EnumerateService = 0x0004,
    Lock = 0x0008,
    QueryLockStatus = 0x0010,
    ModifyBootConfig = 0x0020,
    AllAccess = 0x000F003F,
}

/// <summary>Service access rights (MS-SCMR 2.2.1).</summary>
[Flags]
public enum ServiceAccess : uint
{
    QueryConfig = 0x0001,
    ChangeConfig = 0x0002,
    QueryStatus = 0x0004,
    EnumerateDependents = 0x0008,
    Start = 0x0010,
    Stop = 0x0020,
    PauseContinue = 0x0040,
    Interrogate = 0x0080,
    UserDefinedControl = 0x0100,
    AllAccess = 0x000F01FF,
}

/// <summary>Service type / start type / error control (MS-SCMR 3.1.4.12).</summary>
public static class ServiceConstants
{
    public const uint Win32OwnProcess = 0x00000010;
    public const uint Win32ShareProcess = 0x00000020;

    public const uint StartBoot = 0x00000000;
    public const uint StartSystem = 0x00000001;
    public const uint StartAuto = 0x00000002;
    public const uint StartDemand = 0x00000003;
    public const uint StartDisabled = 0x00000004;

    public const uint ErrorIgnore = 0x00000000;
    public const uint ErrorNormal = 0x00000001;
}

/// <summary>Result of a handle-returning svcctl call.</summary>
public sealed record ScHandleResult(byte[] Handle, uint ReturnCode)
{
    public bool Success => ReturnCode == 0;
}

/// <summary>A service's configuration (MS-SCMR 2.2.15 QUERY_SERVICE_CONFIGW).</summary>
public sealed record ServiceConfig(
    uint ServiceType,
    uint StartType,
    uint ErrorControl,
    uint TagId,
    string BinaryPath,
    string LoadOrderGroup,
    string Dependencies,
    string StartName,
    string DisplayName)
{
    /// <summary>The dwStartType value as a readable name (MS-SCMR 2.2.15).</summary>
    public string StartTypeName => StartType switch
    {
        0 => "BOOT_START",
        1 => "SYSTEM_START",
        2 => "AUTO_START",
        3 => "DEMAND_START",
        4 => "DISABLED",
        _ => $"0x{StartType:X}",
    };
}

/// <summary>One ENUM_SERVICE_STATUSW entry (MS-SCMR 2.2.10): a service's names + status.</summary>
public sealed record ServiceStatusEntry(string Name, string DisplayName, uint ServiceType, uint CurrentState)
{
    /// <summary>The SERVICE_STATUS dwCurrentState value as a readable name (MS-SCMR 2.2.47).</summary>
    public string State => CurrentState switch
    {
        1 => "STOPPED",
        2 => "START_PENDING",
        3 => "STOP_PENDING",
        4 => "RUNNING",
        5 => "CONTINUE_PENDING",
        6 => "PAUSE_PENDING",
        7 => "PAUSED",
        _ => $"0x{CurrentState:X}",
    };
}

/// <summary>
/// Minimal svcctl / Service Control Manager client (MS-SCMR). Port of the parts of
/// impacket's <c>dcerpc.v5.scmr</c> used by the service-execution ("psexec")
/// behavior. Lab use only — the example drives a benign marker command so the SOC
/// can study the wire signature of remote service creation.
/// </summary>
public static class Svcctl
{
    private const ushort OpnumCloseServiceHandle = 0;
    private const ushort OpnumDeleteService = 2;
    private const ushort OpnumCreateServiceW = 12;
    private const ushort OpnumEnumServicesStatusW = 14;
    private const ushort OpnumOpenSCManagerW = 15;
    private const ushort OpnumOpenServiceW = 16;
    private const ushort OpnumQueryServiceConfigW = 17;
    private const ushort OpnumStartServiceW = 19;

    /// <summary>Service type filter: SERVICE_WIN32 (own + share process).</summary>
    public const uint ServiceWin32 = 0x00000030;

    /// <summary>Service state filter: SERVICE_STATE_ALL.</summary>
    public const uint ServiceStateAll = 0x00000003;

    /// <summary>ROpenSCManagerW (opnum 15): connect to the SCM and get a manager handle.</summary>
    public static ScHandleResult OpenScManager(DcerpcPipe pipe, string? machineName, ScManagerAccess access)
    {
        var ndr = new NdrWriter();
        ndr.WriteUniqueString(machineName);  // lpMachineName [in,string,unique]
        ndr.WriteUniqueString(null);         // lpDatabaseName [in,string,unique]
        ndr.WriteUInt32((uint)access);       // dwDesiredAccess
        byte[] stub = pipe.Call(OpnumOpenSCManagerW, ndr.ToArray());

        var reader = new NdrReader(stub);
        byte[] handle = reader.ReadContextHandle();
        uint returnCode = reader.ReadUInt32();
        return new ScHandleResult(handle, returnCode);
    }

    /// <summary>ROpenServiceW (opnum 16): open an existing service by name.</summary>
    public static ScHandleResult OpenService(DcerpcPipe pipe, byte[] scmHandle, string serviceName, ServiceAccess access)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(scmHandle);     // hSCManager [in]
        ndr.WriteReferencedString(serviceName); // lpServiceName [in,string] (ref)
        ndr.WriteUInt32((uint)access);          // dwDesiredAccess
        byte[] stub = pipe.Call(OpnumOpenServiceW, ndr.ToArray());

        var reader = new NdrReader(stub);
        byte[] handle = reader.ReadContextHandle();
        uint returnCode = reader.ReadUInt32();
        return new ScHandleResult(handle, returnCode);
    }

    /// <summary>
    /// REnumServicesStatusW (opnum 14): list the installed services (the services.py
    /// "list" recon). Uses the SCM's two-call buffer-sizing dance — a first call with a
    /// zero buffer returns the required size, the second returns the packed
    /// ENUM_SERVICE_STATUSW records. Requires SC_MANAGER_ENUMERATE_SERVICE on the handle.
    /// </summary>
    public static IReadOnlyList<ServiceStatusEntry> EnumerateServices(
        DcerpcPipe pipe,
        byte[] scmHandle,
        uint serviceType = ServiceWin32,
        uint serviceState = ServiceStateAll)
    {
        (_, uint needed, _, _) = EnumServicesCall(pipe, scmHandle, serviceType, serviceState, 0);
        if (needed == 0)
        {
            return Array.Empty<ServiceStatusEntry>();
        }

        (byte[] buffer, _, uint count, _) = EnumServicesCall(pipe, scmHandle, serviceType, serviceState, needed);
        return ParseServices(buffer, count);
    }

    private static (byte[] Buffer, uint Needed, uint Count, uint ReturnCode) EnumServicesCall(
        DcerpcPipe pipe, byte[] scmHandle, uint serviceType, uint serviceState, uint bufferSize)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(scmHandle); // hSCManager [in]
        ndr.WriteUInt32(serviceType);      // dwServiceType
        ndr.WriteUInt32(serviceState);     // dwServiceState
        ndr.WriteUInt32(bufferSize);       // cbBufSize
        ndr.WriteReferent(false);          // lpResumeIndex [in,out,unique] — null
        byte[] stub = pipe.Call(OpnumEnumServicesStatusW, ndr.ToArray());

        var reader = new NdrReader(stub);
        uint maxCount = reader.ReadUInt32();          // lpBuffer conformant max_count
        byte[] buffer = reader.ReadBytes((int)maxCount);
        uint needed = reader.ReadUInt32();            // pcbBytesNeeded
        uint count = reader.ReadUInt32();             // lpServicesReturned
        reader.ReadUInt32();                          // lpResumeIndex (out)
        uint returnCode = reader.ReadUInt32();        // return (0, or ERROR_MORE_DATA 0xEA)
        return (buffer, needed, count, returnCode);
    }

    /// <summary>
    /// Parses the packed ENUM_SERVICE_STATUSW buffer: <paramref name="count"/> fixed
    /// 36-byte records at the front (two name offsets + a 7-DWORD SERVICE_STATUS), with
    /// the names stored as byte offsets into the same buffer.
    /// </summary>
    public static IReadOnlyList<ServiceStatusEntry> ParseServices(byte[] buffer, uint count)
    {
        const int recordSize = 36; // 2 offsets + SERVICE_STATUS (7 DWORDs)
        var list = new List<ServiceStatusEntry>((int)count);
        for (uint i = 0; i < count; i++)
        {
            int baseOffset = (int)(i * recordSize);
            uint nameOffset = BitConverter.ToUInt32(buffer, baseOffset);
            uint displayOffset = BitConverter.ToUInt32(buffer, baseOffset + 4);
            uint type = BitConverter.ToUInt32(buffer, baseOffset + 8);
            uint state = BitConverter.ToUInt32(buffer, baseOffset + 12);
            list.Add(new ServiceStatusEntry(
                ReadUtf16Z(buffer, (int)nameOffset),
                ReadUtf16Z(buffer, (int)displayOffset),
                type,
                state));
        }

        return list;
    }

    private static string ReadUtf16Z(byte[] buffer, int offset)
    {
        int end = offset;
        while (end + 1 < buffer.Length && !(buffer[end] == 0 && buffer[end + 1] == 0))
        {
            end += 2;
        }

        return System.Text.Encoding.Unicode.GetString(buffer, offset, end - offset);
    }

    /// <summary>
    /// RQueryServiceConfigW (opnum 17): read a service's configuration — binary path,
    /// start type, and logon account (the per-service detail services.py shows). Like
    /// the enumerate call it sizes the out buffer with a zero-size probe first, then
    /// re-queries with the required size. The handle needs SERVICE_QUERY_CONFIG access.
    /// </summary>
    public static ServiceConfig QueryServiceConfig(DcerpcPipe pipe, byte[] serviceHandle)
    {
        (ServiceConfig config, uint needed, _) = QueryConfigCall(pipe, serviceHandle, 0);
        return needed == 0 ? config : QueryConfigCall(pipe, serviceHandle, needed).Config;
    }

    private static (ServiceConfig Config, uint Needed, uint ReturnCode) QueryConfigCall(
        DcerpcPipe pipe, byte[] serviceHandle, uint bufferSize)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(serviceHandle); // hService [in]
        ndr.WriteUInt32(bufferSize);           // cbBufSize
        byte[] stub = pipe.Call(OpnumQueryServiceConfigW, ndr.ToArray());
        return ParseServiceConfig(stub);
    }

    /// <summary>
    /// Parses a QUERY_SERVICE_CONFIGW response: nine fixed fields (three DWORDs, five
    /// deferred string pointers, a tag DWORD), the deferred strings in field order, then
    /// pcbBytesNeeded and the return code. Exposed for tests / offline analysis.
    /// </summary>
    public static (ServiceConfig Config, uint Needed, uint ReturnCode) ParseServiceConfig(byte[] stub)
    {
        var reader = new NdrReader(stub);
        uint type = reader.ReadUInt32();
        uint startType = reader.ReadUInt32();
        uint errorControl = reader.ReadUInt32();
        uint binRef = reader.ReadReferent();
        uint loadRef = reader.ReadReferent();
        uint tagId = reader.ReadUInt32();
        uint depRef = reader.ReadReferent();
        uint startNameRef = reader.ReadReferent();
        uint displayRef = reader.ReadReferent();

        // Deferred conformant-varying strings, in field order for the non-null pointers.
        string binary = binRef != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        string loadOrder = loadRef != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        string dependencies = depRef != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        string startName = startNameRef != 0 ? reader.ReadConformantVaryingString() : string.Empty;
        string display = displayRef != 0 ? reader.ReadConformantVaryingString() : string.Empty;

        uint needed = reader.ReadUInt32();     // pcbBytesNeeded
        uint returnCode = reader.ReadUInt32(); // return (0, or ERROR_INSUFFICIENT_BUFFER 0x7A)

        var config = new ServiceConfig(
            type, startType, errorControl, tagId, binary, loadOrder, dependencies, startName, display);
        return (config, needed, returnCode);
    }

    /// <summary>
    /// RCreateServiceW (opnum 12): create a service running <paramref name="binaryPath"/>.
    /// This is the remote-service-creation step of the psexec technique — lab use only.
    /// </summary>
    public static ScHandleResult CreateService(
        DcerpcPipe pipe,
        byte[] scmHandle,
        string serviceName,
        string displayName,
        string binaryPath,
        ServiceAccess access = ServiceAccess.AllAccess,
        uint serviceType = ServiceConstants.Win32OwnProcess,
        uint startType = ServiceConstants.StartDemand,
        uint errorControl = ServiceConstants.ErrorIgnore)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(scmHandle);          // hSCManager [in]
        ndr.WriteReferencedString(serviceName);     // lpServiceName [in,string] (ref)
        ndr.WriteUniqueString(displayName);         // lpDisplayName [in,string,unique]
        ndr.WriteUInt32((uint)access);              // dwDesiredAccess
        ndr.WriteUInt32(serviceType);               // dwServiceType
        ndr.WriteUInt32(startType);                 // dwStartType
        ndr.WriteUInt32(errorControl);              // dwErrorControl
        ndr.WriteReferencedString(binaryPath);      // lpBinaryPathName [in,string] (ref)
        ndr.WriteUniqueString(null);                // lpLoadOrderGroup [unique]
        ndr.WriteReferent(false);                   // lpdwTagId [in,out,unique]
        ndr.WriteReferent(false);                   // lpDependencies [unique]
        ndr.WriteUInt32(0);                         // dwDependSize
        ndr.WriteUniqueString(null);                // lpServiceStartName [unique]
        ndr.WriteReferent(false);                   // lpPassword [unique]
        ndr.WriteUInt32(0);                         // dwPwSize
        byte[] stub = pipe.Call(OpnumCreateServiceW, ndr.ToArray());

        var reader = new NdrReader(stub);
        uint tagReferent = reader.ReadReferent(); // lpdwTagId out
        if (tagReferent != 0)
        {
            reader.ReadUInt32();
        }

        byte[] handle = reader.ReadContextHandle();
        uint returnCode = reader.ReadUInt32();
        return new ScHandleResult(handle, returnCode);
    }

    /// <summary>RStartServiceW (opnum 19): start a service (no arguments).</summary>
    public static uint StartService(DcerpcPipe pipe, byte[] serviceHandle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(serviceHandle); // hService [in]
        ndr.WriteUInt32(0);                    // argc
        ndr.WriteReferent(false);              // argv [in,unique,size_is(argc)]
        byte[] stub = pipe.Call(OpnumStartServiceW, ndr.ToArray());

        var reader = new NdrReader(stub);
        return reader.ReadUInt32(); // return code
    }

    /// <summary>RDeleteService (opnum 2): mark a service for deletion (lab teardown).</summary>
    public static uint DeleteService(DcerpcPipe pipe, byte[] serviceHandle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(serviceHandle);
        byte[] stub = pipe.Call(OpnumDeleteService, ndr.ToArray());

        var reader = new NdrReader(stub);
        return reader.ReadUInt32();
    }

    /// <summary>RCloseServiceHandle (opnum 0): release an SCM or service handle.</summary>
    public static uint CloseServiceHandle(DcerpcPipe pipe, byte[] handle)
    {
        var ndr = new NdrWriter();
        ndr.WriteContextHandle(handle);
        byte[] stub = pipe.Call(OpnumCloseServiceHandle, ndr.ToArray());

        var reader = new NdrReader(stub);
        reader.ReadContextHandle(); // the (now-nulled) handle is echoed back
        return reader.ReadUInt32(); // return code
    }

    /// <summary>Names the common Win32 error codes these calls return.</summary>
    public static string DescribeWin32(uint code) => code switch
    {
        0 => "ERROR_SUCCESS",
        5 => "ERROR_ACCESS_DENIED",
        1056 => "ERROR_SERVICE_ALREADY_RUNNING",
        1072 => "ERROR_SERVICE_MARKED_FOR_DELETE",
        1073 => "ERROR_SERVICE_EXISTS",
        1053 => "ERROR_SERVICE_REQUEST_TIMEOUT",
        _ => $"0x{code:X8} ({code})",
    };
}
