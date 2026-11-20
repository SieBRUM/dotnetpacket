using System.Text.RegularExpressions;

namespace DotNetPacket.Examples;

/// <summary>
/// Credentials + target, parsed the impacket way from a single token:
/// <c>[[domain/]username[:password]@]host</c>. There is no separate <c>user</c>/<c>password</c>
/// positional — everything rides in the target, exactly like impacket's <c>proto.py [opts] target</c>.
/// The parse is byte-for-byte impacket's <c>parse_target</c> (regex + the <c>@</c>-in-password fixup),
/// so a password may contain <c>@</c>, <c>:</c> and <c>/</c> (the host separator is the <b>last</b>
/// <c>@</c>). The password is optional: omit the <c>:password</c> when authenticating with
/// <c>-hashes</c> / <c>-aesKey</c> / <c>-k</c> / a ccache / <c>-no-pass</c>. <see cref="NextIndex"/> is
/// where the command's own positionals (share, command, port, …) begin — the token after the target.
/// </summary>
internal sealed record Creds(string Host, string User, string? Password, string? Domain, int NextIndex)
{
    // impacket/examples/utils.py: target_regex = re.compile("(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)")
    private static readonly Regex TargetRegex =
        new(@"^(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)$", RegexOptions.Compiled);

    /// <summary>The domain (from the target's <c>domain/</c> prefix), or empty.</summary>
    public string DomainOrEmpty => Domain ?? string.Empty;

    /// <summary>The password to hand a login/bind call (empty when a hash/ticket supplies the secret).</summary>
    public string PasswordOrEmpty => Password ?? string.Empty;

    /// <summary>
    /// Pure parse of an impacket target string into (domain, user, password, host). Mirrors impacket's
    /// <c>parse_target</c> exactly, including the fixup that reattaches a password containing <c>@</c>.
    /// <paramref name="hasPassword"/> is true when a password was explicitly present (a <c>:</c> in the
    /// credentials, or an <c>@</c>-fixup) — used to tell "empty password" from "no password given".
    /// </summary>
    public static (string Domain, string User, string Password, string Host, bool HasPassword) ParseTarget(string token)
    {
        Match m = TargetRegex.Match(token);
        string domain = m.Groups[1].Value;
        string user = m.Groups[2].Value;
        bool hasPassword = m.Groups[3].Success;
        string password = m.Groups[3].Value;
        string host = m.Groups[4].Value;

        // impacket: "In case the password contains '@'" — the real host separator was the LAST '@'.
        int lastAt = host.LastIndexOf('@');
        if (lastAt >= 0)
        {
            password = password + "@" + host[..lastAt];
            host = host[(lastAt + 1)..];
            hasPassword = true;
        }

        return (domain, user, password, host, hasPassword);
    }

    /// <summary>Parses the impacket target at <paramref name="targetIndex"/>, printing usage and exiting on error.</summary>
    public static Creds ResolveOrExit(string[] args, int targetIndex, string usage, bool allowEmptyUser = false)
    {
        try
        {
            return Resolve(args, targetIndex, usage, allowEmptyUser);
        }
        catch (CredsUsageException ex)
        {
            Console.Error.WriteLine(ex.Message);
            Environment.Exit(2);
            throw; // unreachable
        }
    }

    /// <summary>Parses the impacket target <c>[[domain/]username[:password]@]host</c>.</summary>
    public static Creds Resolve(string[] args, int targetIndex, string usage, bool allowEmptyUser = false)
    {
        if (targetIndex >= args.Length)
        {
            throw new CredsUsageException(usage);
        }

        string token = args[targetIndex];
        (string domain, string user, string password, string host, bool hasPassword) = ParseTarget(token);

        if (host.Length == 0)
        {
            throw new CredsUsageException($"Target has no host.\n{usage}");
        }

        if (user.Length == 0 && !allowEmptyUser)
        {
            // A bare host (no '@') lands here too — guide the user to the target form.
            throw new CredsUsageException(
                $"Target '{token}' has no username — use [domain/]username[:password]@host.\n{usage}");
        }

        if (!hasPassword && user.Length > 0 && !GlobalOptions.PasswordOptional)
        {
            throw new CredsUsageException(
                "No password in the target, and no -hashes / -aesKey / -k / -ccache / -no-pass given.\n" + usage);
        }

        return new Creds(host, user, hasPassword ? password : null,
            string.IsNullOrEmpty(domain) ? null : domain, targetIndex + 1);
    }
}

/// <summary>Thrown by <see cref="Creds.Resolve"/> when the credential arguments are missing/invalid.</summary>
internal sealed class CredsUsageException(string message) : Exception(message);
