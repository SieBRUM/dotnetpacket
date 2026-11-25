namespace DotNetPacket.Core.Diagnostics;

/// <summary>Verbosity for <see cref="PacketTrace"/>.</summary>
public enum TraceLevel
{
    /// <summary>No diagnostics (the default; commands print only their own output).</summary>
    Off = 0,

    /// <summary>One line per connect and per message (direction + channel + byte count), no hex.</summary>
    Verbose = 1,

    /// <summary><see cref="Verbose"/> plus a hex dump of every message on the wire.</summary>
    Debug = 2,
}

/// <summary>
/// A process-wide, opt-in diagnostics sink the transports write to so that <em>every</em> command
/// gains packet-level tracing without each command handler needing its own flag. It is wired on by
/// the CLI's global <c>-debug</c> / <c>-verbose</c> options (see <c>GlobalOptions</c>).
/// </summary>
/// <remarks>
/// This is purely an observability aid (stderr diagnostics) — it never changes a single byte on the
/// wire, so it is realism-neutral and matches the project's "observable and inspectable" doctrine
/// (<c>docs/REALISM.md</c>, <c>CLAUDE.md</c>). Transports call <see cref="Sent"/>/<see cref="Received"/>
/// at the point a whole logical message is assembled, and <see cref="Event"/> for notable steps
/// (connect, dialect chosen, bind result). All output goes to <see cref="Out"/> (default
/// <see cref="Console.Error"/>) so it never pollutes a command's stdout (hex dumps, hashes, pcaps).
/// </remarks>
public static class PacketTrace
{
    /// <summary>Current verbosity. <see cref="TraceLevel.Off"/> unless the CLI enables tracing.</summary>
    public static TraceLevel Level { get; set; } = TraceLevel.Off;

    /// <summary>Where diagnostics are written. Defaults to <see cref="Console.Error"/>.</summary>
    public static TextWriter Out { get; set; } = Console.Error;

    /// <summary>True when at least <see cref="TraceLevel.Verbose"/> tracing is on.</summary>
    public static bool IsVerbose => Level >= TraceLevel.Verbose;

    /// <summary>True when full hex-dump (<see cref="TraceLevel.Debug"/>) tracing is on.</summary>
    public static bool IsDebug => Level >= TraceLevel.Debug;

    /// <summary>Logs a notable protocol step (shown at <see cref="TraceLevel.Verbose"/> and above).</summary>
    public static void Event(string channel, string message)
    {
        if (Level < TraceLevel.Verbose)
        {
            return;
        }

        Out.WriteLine($"[trace {channel}] {message}");
    }

    /// <summary>Traces an outbound message on <paramref name="channel"/> (e.g. "smb", "ldap", "krb5").</summary>
    public static void Sent(string channel, ReadOnlySpan<byte> data) => Wire(channel, "-->", data);

    /// <summary>Traces an inbound message on <paramref name="channel"/>.</summary>
    public static void Received(string channel, ReadOnlySpan<byte> data) => Wire(channel, "<--", data);

    private static void Wire(string channel, string arrow, ReadOnlySpan<byte> data)
    {
        if (Level < TraceLevel.Verbose)
        {
            return;
        }

        Out.WriteLine($"[trace {channel}] {arrow} {data.Length} bytes");
        if (Level >= TraceLevel.Debug)
        {
            Out.Write(Hex.Dump(data));
        }
    }

    /// <summary>
    /// Parses a verbosity name (<c>off</c>/<c>verbose</c>/<c>debug</c>, case-insensitive) for the CLI.
    /// Unknown values map to <see cref="TraceLevel.Verbose"/> so a bare <c>-verbose</c> still works.
    /// </summary>
    public static TraceLevel ParseLevel(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "off" or "none" or "0" => TraceLevel.Off,
        "debug" or "2" => TraceLevel.Debug,
        _ => TraceLevel.Verbose,
    };
}
