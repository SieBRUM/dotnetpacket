using DotNetPacket.Examples;
using Xunit;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// Guards the command help registry (<see cref="CommandHelp"/>). The old hand-maintained usage block
/// drifted out of sync with the real argument parsing (documenting a credential form that no longer
/// existed); these pin the registry's internal consistency so a careless edit fails the build.
/// </summary>
public class HelpTests
{
    [Fact]
    public void CommandNames_AreUniqueAndNonEmpty()
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (CommandDoc d in CommandHelp.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(d.Name));
            Assert.True(seen.Add(d.Name), $"duplicate command doc: {d.Name}");
        }
    }

    [Fact]
    public void EveryCommand_HasCategoryAndSummary()
    {
        foreach (CommandDoc d in CommandHelp.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(d.Category), $"{d.Name}: empty category");
            Assert.False(string.IsNullOrWhiteSpace(d.Summary), $"{d.Name}: empty summary");
        }
    }

    [Fact]
    public void EveryExample_InvokesItsOwnCommand()
    {
        // An example for `rpc-shares` must actually start with `rpc-shares` (catches copy-paste slips).
        foreach (CommandDoc d in CommandHelp.All)
        {
            foreach (string ex in d.Examples ?? Array.Empty<string>())
            {
                Assert.True(
                    ex == d.Name || ex.StartsWith(d.Name + " ", StringComparison.Ordinal),
                    $"{d.Name}: example does not invoke the command: '{ex}'");
            }
        }
    }

    [Theory]
    [InlineData("dcsync-k")]
    [InlineData("rpc-epm-map")]
    [InlineData("smb-header")]
    public void PrintCommand_KnownCommand_ReturnsZero(string name)
    {
        Assert.Equal(0, CommandHelp.PrintCommand(name));
    }

    [Fact]
    public void PrintCommand_UnknownCommand_ReturnsOne()
    {
        Assert.Equal(1, CommandHelp.PrintCommand("no-such-command"));
    }
}
