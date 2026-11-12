using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class SmbExecTests
{
    // impacket's smbexec emits a fixed, heavily-signatured service binary path. The point of this
    // port is to reproduce the BEHAVIOUR while diverging on the runtime-specific string tokens, so a
    // SOC can confirm a brittle string IOC does NOT catch the .NET reimplementation but a behavioural
    // detection does. These tests pin BOTH sides of that: the behaviour is present, and impacket's
    // signature tokens are absent.

    [Fact]
    public void BuildCmd_KeepsTheBehaviour()
    {
        string cmd = SmbExecCommand.BuildCmd("whoami", "C$", "aB3kZ9qLmN0pQrXt", @"%TEMP%\Xy7_script.cmd");

        // Drives a command interpreter, redirects output to the share file, writes+runs+deletes a
        // temp script - the behaviour a detection should key on (survives a rewrite).
        Assert.Contains("cmd.exe /c", cmd);
        Assert.Contains(@"\\%COMPUTERNAME%\C$\", cmd);   // output redirected to the readable share
        Assert.Contains("2^>^&1", cmd);                  // stderr merged into the captured output
        Assert.Contains(@"%TEMP%\Xy7_script.cmd", cmd);  // the temp script is referenced
        Assert.Contains("del ", cmd);                    // and removed afterwards
    }

    [Fact]
    public void BuildCmd_DivergesFromImpacketSignatureTokens()
    {
        string cmd = SmbExecCommand.BuildCmd("whoami", "C$", "aB3kZ9qLmN0pQrXt", @"%TEMP%\Xy7_script.cmd");

        // The tokens published smbexec signatures match on must NOT appear.
        Assert.DoesNotContain("%COMSPEC%", cmd);
        Assert.DoesNotContain("/Q /c", cmd);
        Assert.DoesNotContain("__output_", cmd);
        Assert.DoesNotContain(".bat", cmd);
        Assert.DoesNotContain("%SYSTEMROOT%", cmd);
    }

    [Fact]
    public void OutputFilename_HasNoImpacketPrefix()
    {
        string name = SmbExecCommand.OutputFilename(new Random(1));
        Assert.DoesNotContain("__output_", name);          // impacket: "__output_" + 8 letters
        Assert.Equal(16, name.Length);                     // impacket: 8
        Assert.All(name, c => Assert.True(char.IsAsciiLetterOrDigit(c)));
    }

    [Fact]
    public void ScriptFile_IsUnderTempWithCmdExtension()
    {
        string script = SmbExecCommand.ScriptFile(new Random(1));
        Assert.StartsWith(@"%TEMP%\", script);             // impacket: %SYSTEMROOT%
        Assert.EndsWith(".cmd", script);                   // impacket: .bat
        Assert.DoesNotContain(".bat", script);
    }

    [Fact]
    public void RandomAlphanumeric_IncludesDigits_AndIsSeedDeterministic()
    {
        // impacket draws from string.ascii_letters (letters only); ours includes digits - a
        // deliberate fingerprint divergence.
        string a = SmbExecCommand.RandomAlphanumeric(new Random(42), 256);
        string b = SmbExecCommand.RandomAlphanumeric(new Random(42), 256);
        Assert.Equal(a, b);                                 // same seed -> same string
        Assert.Equal(256, a.Length);
        Assert.All(a, c => Assert.True(char.IsAsciiLetterOrDigit(c), $"'{c}' is not alphanumeric"));
        Assert.Contains(a, char.IsAsciiDigit);              // digits do appear (not in impacket's alphabet)
    }
}
