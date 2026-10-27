using Xunit;
using DepRisk.Core;

namespace DepRisk.Core.Tests;

/// <summary>
/// Exit codes are a public contract (README, "Exit codes"). If one of these fails,
/// you are changing the contract: write an ADR and bump the major version.
/// </summary>
public class ExitCodeContractTests
{
    [Theory]
    [InlineData(ExitCode.Success, 0)]
    [InlineData(ExitCode.PolicyGateFailed, 1)]
    [InlineData(ExitCode.PlanVerificationFailed, 2)]
    [InlineData(ExitCode.AuditIntegrityFailure, 3)]
    [InlineData(ExitCode.InvalidInput, 4)]
    [InlineData(ExitCode.InternalError, 5)]
    public void Exit_code_values_are_stable(ExitCode code, int expected)
    {
        Assert.Equal(expected, (int)code);
    }

    [Fact]
    public void No_undocumented_exit_codes_exist()
    {
        Assert.Equal(6, Enum.GetValues<ExitCode>().Length);
    }
}
