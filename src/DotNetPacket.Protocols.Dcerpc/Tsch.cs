namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>
/// Result of a SchRpcGetLastRunInfo call: the last run time (year 0 means "never run yet") plus
/// the task's last return code.
/// </summary>
public sealed record SchLastRunInfo(ushort Year, uint LastReturnCode, uint ReturnCode)
{
    public bool HasRun => Year != 0;
}

/// <summary>
/// Client for the Task Scheduler service (ITaskSchedulerService, MS-TSCH) over DCERPC — the
/// subset atexec.py uses to run a command on a remote host: register an XML task, run it, poll its
/// last-run info, then delete it. Port of the <c>hSchRpc*</c> helpers in impacket's
/// <c>impacket.dcerpc.v5.tsch</c>. Windows-only on the wire: Samba does not implement this service.
/// </summary>
public static class Tsch
{
    private const ushort OpnumRegisterTask = 1;
    private const ushort OpnumRun = 12;
    private const ushort OpnumDelete = 13;
    private const ushort OpnumGetLastRunInfo = 16;

    /// <summary>TASK_CREATE flag for SchRpcRegisterTask.</summary>
    public const uint TaskCreate = 2;

    /// <summary>TASK_LOGON_NONE.</summary>
    public const uint TaskLogonNone = 0;

    /// <summary>
    /// SchRpcRegisterTask (opnum 1): register <paramref name="xml"/> as a task at
    /// <paramref name="path"/> (e.g. <c>\MyTask</c>). Returns the NT/HRESULT ErrorCode (0 = ok).
    /// </summary>
    public static uint RegisterTask(DcerpcPipe pipe, string path, string xml, uint flags = TaskCreate, uint logonType = TaskLogonNone)
    {
        byte[] stub = pipe.Call(OpnumRegisterTask, EncodeRegisterTask(path, xml, flags, logonType));
        return ReadTrailingErrorCode(stub);
    }

    /// <summary>SchRpcRun (opnum 12): run the task at <paramref name="path"/> now. Returns the ErrorCode.</summary>
    public static uint Run(DcerpcPipe pipe, string path)
    {
        byte[] stub = pipe.Call(OpnumRun, EncodeRun(path));
        return ReadTrailingErrorCode(stub);
    }

    /// <summary>SchRpcDelete (opnum 13): delete the task at <paramref name="path"/>. Returns the ErrorCode.</summary>
    public static uint Delete(DcerpcPipe pipe, string path)
    {
        byte[] stub = pipe.Call(OpnumDelete, EncodeDelete(path));
        return ReadTrailingErrorCode(stub);
    }

    /// <summary>SchRpcGetLastRunInfo (opnum 16): read the task's last run time + return code.</summary>
    public static SchLastRunInfo GetLastRunInfo(DcerpcPipe pipe, string path)
    {
        byte[] stub = pipe.Call(OpnumGetLastRunInfo, EncodeGetLastRunInfo(path));
        var reader = new NdrReader(stub);
        ushort year = reader.ReadUInt16();        // SYSTEMTIME.wYear (first field)
        // Skip the remaining 7 SYSTEMTIME WORDs (month..milliseconds) = 14 bytes.
        for (int i = 0; i < 7; i++)
        {
            reader.ReadUInt16();
        }

        uint lastReturnCode = reader.ReadUInt32();
        uint rc = reader.ReadUInt32();
        return new SchLastRunInfo(year, lastReturnCode, rc);
    }

    /// <summary>
    /// Builds the scheduled-task XML atexec registers: a hidden, run-on-demand task that runs
    /// <paramref name="command"/> with <paramref name="arguments"/> as LocalSystem. Verbatim port
    /// of the template in impacket's <c>atexec.py</c> (without the optional Author log-tampering).
    /// </summary>
    public static string BuildTaskXml(string command, string arguments) =>
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n" +
        "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n" +
        "  <Triggers>\n" +
        "    <CalendarTrigger>\n" +
        "      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>\n" +
        "      <Enabled>true</Enabled>\n" +
        "      <ScheduleByDay>\n" +
        "        <DaysInterval>1</DaysInterval>\n" +
        "      </ScheduleByDay>\n" +
        "    </CalendarTrigger>\n" +
        "  </Triggers>\n" +
        "  <Principals>\n" +
        "    <Principal id=\"LocalSystem\">\n" +
        "      <UserId>S-1-5-18</UserId>\n" +
        "      <RunLevel>HighestAvailable</RunLevel>\n" +
        "    </Principal>\n" +
        "  </Principals>\n" +
        "  <Settings>\n" +
        "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n" +
        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n" +
        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n" +
        "    <AllowHardTerminate>true</AllowHardTerminate>\n" +
        "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n" +
        "    <IdleSettings>\n" +
        "      <StopOnIdleEnd>true</StopOnIdleEnd>\n" +
        "      <RestartOnIdle>false</RestartOnIdle>\n" +
        "    </IdleSettings>\n" +
        "    <AllowStartOnDemand>true</AllowStartOnDemand>\n" +
        "    <Enabled>true</Enabled>\n" +
        "    <Hidden>true</Hidden>\n" +
        "    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n" +
        "    <WakeToRun>false</WakeToRun>\n" +
        "    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>\n" +
        "    <Priority>7</Priority>\n" +
        "  </Settings>\n" +
        "  <Actions Context=\"LocalSystem\">\n" +
        "    <Exec>\n" +
        $"      <Command>{XmlEscape(command)}</Command>\n" +
        $"      <Arguments>{XmlEscape(arguments)}</Arguments>\n" +
        "    </Exec>\n" +
        "  </Actions>\n" +
        "</Task>\n        ";

    private static string XmlEscape(string s) => s
        .Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
        .Replace("\"", "&quot;").Replace("'", "&apos;");

    // --- request encoders (exposed for tests) ---

    /// <summary>SchRpcRegisterTask request: path (LPWSTR), xml (WSTR), flags, sddl=NULL, logonType, cCreds=0, pCreds=NULL.</summary>
    public static byte[] EncodeRegisterTask(string path, string xml, uint flags, uint logonType)
    {
        var ndr = new NdrWriter();
        ndr.WriteReferent(true);                   // path LPWSTR (unique ptr, present)
        ndr.WriteConformantVaryingString(path);
        ndr.WriteConformantVaryingString(xml);     // xml WSTR (inline)
        ndr.WriteUInt32(flags);
        ndr.WriteReferent(false);                  // sddl LPWSTR = NULL
        ndr.WriteUInt32(logonType);
        ndr.WriteUInt32(0);                        // cCreds
        ndr.WriteReferent(false);                  // pCreds = NULL
        return ndr.ToArray();
    }

    /// <summary>SchRpcRun request: path (WSTR), cArgs=0, pArgs=NULL, flags=0, sessionId=0, user=NULL.</summary>
    public static byte[] EncodeRun(string path)
    {
        var ndr = new NdrWriter();
        ndr.WriteConformantVaryingString(path);
        ndr.WriteUInt32(0);        // cArgs
        ndr.WriteReferent(false);  // pArgs = NULL
        ndr.WriteUInt32(0);        // flags
        ndr.WriteUInt32(0);        // sessionId
        ndr.WriteReferent(false);  // user = NULL
        return ndr.ToArray();
    }

    /// <summary>SchRpcDelete request: path (WSTR), flags=0.</summary>
    public static byte[] EncodeDelete(string path)
    {
        var ndr = new NdrWriter();
        ndr.WriteConformantVaryingString(path);
        ndr.WriteUInt32(0);        // flags
        return ndr.ToArray();
    }

    /// <summary>SchRpcGetLastRunInfo request: path (WSTR).</summary>
    public static byte[] EncodeGetLastRunInfo(string path)
    {
        var ndr = new NdrWriter();
        ndr.WriteConformantVaryingString(path);
        return ndr.ToArray();
    }

    // The ErrorCode is the final 4 bytes of these responses (after the OUT params).
    private static uint ReadTrailingErrorCode(byte[] stub)
    {
        if (stub.Length < 4)
        {
            throw new InvalidDataException("tsch response too short.");
        }

        return (uint)(stub[^4] | (stub[^3] << 8) | (stub[^2] << 16) | (stub[^1] << 24));
    }
}
