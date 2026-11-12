using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class SmbExecTests
{
    // The behavioural signature of smbexec: the %COMSPEC% service binary path.
    // Pinned to stock impacket's examples/smbexec.py RemoteShell.execute_remote
    // (cmd shell type, SHARE mode) with fixed names — see the oracle in the commit notes.
    [Fact]
    public void BuildCmd_MatchesImpacketExecuteRemote()
    {
        string command = SmbExecCommand.BuildCmd(
            "whoami",
            "C$",
            "__output_AbCdEfGh",
            @"%SYSTEMROOT%\MnOpQrSt.bat");

        const string expected =
            @"%COMSPEC% /Q /c echo whoami ^> \\%COMPUTERNAME%\C$\__output_AbCdEfGh 2^>^&1 > " +
            @"%SYSTEMROOT%\MnOpQrSt.bat & %COMSPEC% /Q /c %SYSTEMROOT%\MnOpQrSt.bat & del %SYSTEMROOT%\MnOpQrSt.bat";

        Assert.Equal(expected, command);
    }

    [Fact]
    public void OutputFilename_HasImpacketPrefixAndLength()
    {
        string name = SmbExecCommand.OutputFilename(new Random(1));
        Assert.StartsWith("__output_", name);
        Assert.Equal("__output_".Length + 8, name.Length);
    }

    [Fact]
    public void BatchFile_IsUnderSystemRootWithBatExtension()
    {
        string batch = SmbExecCommand.BatchFile(new Random(1));
        Assert.StartsWith(@"%SYSTEMROOT%\", batch);
        Assert.EndsWith(".bat", batch);
    }

    [Fact]
    public void RandomLetters_DrawsOnlyAsciiLetters_AndIsSeedDeterministic()
    {
        // impacket draws from string.ascii_letters (A-Za-z) only.
        string a = SmbExecCommand.RandomLetters(new Random(42), 64);
        string b = SmbExecCommand.RandomLetters(new Random(42), 64);
        Assert.Equal(a, b); // same seed -> same string
        Assert.Equal(64, a.Length);
        Assert.All(a, c => Assert.True(char.IsAsciiLetter(c), $"'{c}' is not an ASCII letter"));
    }
}
