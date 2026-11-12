namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>
/// Builds the service <c>lpBinaryPathName</c> that the smbexec technique runs — the
/// behavioural signature a SOC detects. Port of
/// <c>examples/smbexec.py</c> <c>RemoteShell.execute_remote</c>.
///
/// <para>smbexec does not upload a service binary (unlike psexec/RemComSvc). Instead it
/// creates a one-shot service whose binary path is a <c>cmd.exe</c> line that: writes the
/// command into a throwaway <c>.bat</c> under <c>%SYSTEMROOT%</c> (redirecting its output to
/// a file on a readable share), runs that batch, then deletes it. The caller reads the
/// redirected output back off the share. The service never starts cleanly (the SCM times it
/// out — it is not a real service), which is itself part of the on-the-wire tell, along with
/// the <c>%COMSPEC% /Q /c</c> command and the per-invocation random service/batch/output
/// names.</para>
///
/// <para>Lab use only (see CLAUDE.md scope). The output of this class goes straight into
/// <see cref="Svcctl.CreateService"/> as the binary path.</para>
/// </summary>
public static class SmbExecCommand
{
    /// <summary>The command processor prefix smbexec prepends to each leg (<c>%COMSPEC% /Q /c </c>).</summary>
    public const string Shell = "%COMSPEC% /Q /c ";

    /// <summary>
    /// Builds the cmd shell binary path for <paramref name="command"/>, matching smbexec's
    /// <c>execute_remote</c> (cmd shell type, SHARE mode) byte-for-byte.
    /// </summary>
    /// <param name="command">The command to run on the target (e.g. <c>whoami</c>).</param>
    /// <param name="share">The share the output is redirected to and grabbed from (impacket default <c>C$</c>).</param>
    /// <param name="outputFilename">The output file name on that share (see <see cref="OutputFilename"/>).</param>
    /// <param name="batchFile">The throwaway batch path (see <see cref="BatchFile"/>).</param>
    public static string BuildCmd(string command, string share, string outputFilename, string batchFile)
    {
        // \\%COMPUTERNAME%\<share>\<outputFilename> — the target writes its own output here.
        string output = @"\\%COMPUTERNAME%\" + share + "\\" + outputFilename;

        // %COMSPEC% /Q /c echo <cmd> ^> <output> 2^>^&1 > <batch> & %COMSPEC% /Q /c <batch> & del <batch>
        string result = Shell + "echo " + command + " ^> " + output + " 2^>^&1 > " + batchFile +
                        " & " + Shell + batchFile;
        result += " & " + "del " + batchFile;
        return result;
    }

    /// <summary>
    /// The output file name smbexec uses: <c>__output_</c> + 8 random ASCII letters.
    /// Deterministic when <paramref name="random"/> is seeded (for tests).
    /// </summary>
    public static string OutputFilename(Random random) => "__output_" + RandomLetters(random, 8);

    /// <summary>
    /// The throwaway batch path smbexec uses: <c>%SYSTEMROOT%\</c> + 8 random ASCII letters + <c>.bat</c>.
    /// </summary>
    public static string BatchFile(Random random) => @"%SYSTEMROOT%\" + RandomLetters(random, 8) + ".bat";

    /// <summary>A service name in smbexec's style: 8 random ASCII letters.</summary>
    public static string ServiceName(Random random) => RandomLetters(random, 8);

    /// <summary>
    /// <paramref name="count"/> characters drawn from <c>string.ascii_letters</c> (A–Z, a–z),
    /// the same alphabet impacket's <c>random.choice(string.ascii_letters)</c> draws from.
    /// </summary>
    public static string RandomLetters(Random random, int count)
    {
        const string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        char[] chars = new char[count];
        for (int i = 0; i < count; i++)
        {
            chars[i] = alphabet[random.Next(alphabet.Length)];
        }

        return new string(chars);
    }
}
