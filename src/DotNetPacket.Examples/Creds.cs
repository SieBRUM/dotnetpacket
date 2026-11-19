namespace DotNetPacket.Examples;

/// <summary>
/// Credentials + target, parsed the impacket way from a single token:
/// <c>[[domain/]username[:password]@]host</c>. There is no separate <c>user</c>/<c>password</c>
/// positional — everything rides in the target, exactly like impacket's <c>proto.py [opts] target</c>.
/// The password is optional: omit the <c>:password</c> when authenticating with <c>-hashes</c> /
/// <c>-aesKey</c> / <c>-k</c> / a ccache / <c>-no-pass</c>. <see cref="NextIndex"/> is where the
/// command's own positionals (share, command, port, …) begin — always the token after the target.
/// </summary>
internal sealed record Creds(string Host, string User, string? Password, string? Domain, int NextIndex)
{
    /// <summary>The domain (from the target's <c>domain/</c> prefix), or empty.</summary>
    public string DomainOrEmpty => Domain ?? string.Empty;

    /// <summary>The password to hand a login/bind call (empty when a hash/ticket supplies the secret).</summary>
    public string PasswordOrEmpty => Password ?? string.Empty;

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
        int at = token.IndexOf('@');
        if (at < 0)
        {
            throw new CredsUsageException(
                $"Target must be [[domain/]username[:password]@]host (got '{token}').\n{usage}");
        }

        string credPart = token[..at];
        string host = token[(at + 1)..];
        if (host.Length == 0)
        {
            throw new CredsUsageException($"Target has no host after '@'.\n{usage}");
        }

        string? domain = null;
        int slash = credPart.IndexOf('/');
        if (slash >= 0)
        {
            domain = credPart[..slash];
            credPart = credPart[(slash + 1)..];
        }

        string user;
        string? password = null;
        int colon = credPart.IndexOf(':');
        if (colon >= 0)
        {
            user = credPart[..colon];
            password = credPart[(colon + 1)..];
        }
        else
        {
            user = credPart;
        }

        if (user.Length == 0 && !allowEmptyUser)
        {
            throw new CredsUsageException($"Target has no username.\n{usage}");
        }

        if (password is null && user.Length > 0 && !GlobalOptions.PasswordOptional)
        {
            throw new CredsUsageException(
                "No password in the target, and no -hashes / -aesKey / -k / -ccache / -no-pass given.\n" + usage);
        }

        return new Creds(host, user, password, string.IsNullOrEmpty(domain) ? null : domain, targetIndex + 1);
    }
}

/// <summary>Thrown by <see cref="Creds.Resolve"/> when the credential arguments are missing/invalid.</summary>
internal sealed class CredsUsageException(string message) : Exception(message);
