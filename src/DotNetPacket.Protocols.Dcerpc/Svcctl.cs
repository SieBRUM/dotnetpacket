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
    private const ushort OpnumOpenSCManagerW = 15;
    private const ushort OpnumOpenServiceW = 16;
    private const ushort OpnumStartServiceW = 19;

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
