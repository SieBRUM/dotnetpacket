using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class ServiceStatusTests
{
    // Verbatim RQueryServiceStatus (opnum 6) response stub captured against a Samba AD DC for the
    // Spooler service: SERVICE_STATUS { dwServiceType=0x110, dwCurrentState=4 (RUNNING),
    // dwControlsAccepted=1 (STOP), exit codes 0, checkpoint 0, wait hint 0 }, then NTSTATUS 0.
    private const string StatusResp =
        "1001000004000000010000000000000000000000000000000000000000000000";

    [Fact]
    public void ParseServiceStatus_ReadsRunStateAndControls()
    {
        ServiceStatus s = Svcctl.ParseServiceStatus(Convert.FromHexString(StatusResp));

        Assert.Equal(0x110u, s.ServiceType);
        Assert.Equal(4u, s.CurrentState);
        Assert.Equal("RUNNING", s.State);
        Assert.Equal(1u, s.ControlsAccepted);
        Assert.Equal("STOP", s.ControlsAcceptedText);
        Assert.Equal(0u, s.Win32ExitCode);
        Assert.Equal(0u, s.CheckPoint);
        Assert.Equal(0u, s.WaitHint);
    }

    [Fact]
    public void ControlsAcceptedText_DecodesFlagCombination()
    {
        Assert.Equal("STOP | SHUTDOWN", Svcctl.ControlsAcceptedText(0x5));
        Assert.Equal("(none)", Svcctl.ControlsAcceptedText(0));
    }
}
