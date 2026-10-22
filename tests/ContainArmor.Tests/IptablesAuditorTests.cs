using ContainArmor.Engine.Models;
using ContainArmor.Engine.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace ContainArmor.Tests;

public class IptablesAuditorTests
{
    private readonly IptablesAuditor _auditor;

    public IptablesAuditorTests()
    {
        _auditor = new IptablesAuditor(NullLogger<IptablesAuditor>.Instance);
    }

    [Fact]
    public async Task AuditIptablesChains_DefaultChains_DetectsDockerUserChainGap()
    {
        // Arrange & Act
        var audit = await _auditor.AuditIptablesChainsAsync();

        // Assert
        Assert.NotNull(audit);
        Assert.False(audit.DockerUserChainProperlySecured);
        Assert.NotEmpty(audit.SecurityWarnings);
        Assert.Contains(audit.SecurityWarnings, w => w.Contains("DOCKER-USER"));

        var dockerUserChain = audit.Chains.FirstOrDefault(c => c.ChainName == "DOCKER-USER");
        Assert.NotNull(dockerUserChain);
        Assert.Contains(dockerUserChain.Rules, r => r.Target == "RETURN");
    }

    [Fact]
    public async Task AuditIptablesChains_ForwardChain_FlagsPromiscuousBridgeAccept()
    {
        // Arrange & Act
        var audit = await _auditor.AuditIptablesChainsAsync();

        // Assert
        var forwardChain = audit.Chains.FirstOrDefault(c => c.ChainName == "FORWARD");
        Assert.NotNull(forwardChain);

        var promiscuousRule = forwardChain.Rules.FirstOrDefault(r => r.InInterface == "docker0" && r.OutInterface == "docker0" && r.Target == "ACCEPT");
        Assert.NotNull(promiscuousRule);
        Assert.Equal(RuleStatus.DangerousPromiscuous, promiscuousRule.Status);
    }

    [Fact]
    public async Task AuditIptablesChains_CrossReferencesBreaches_InjectsTargetedDropFixes()
    {
        // Arrange
        var breaches = new List<IsolationBreach>
        {
            new()
            {
                SourceContainer = "attacker-c2",
                TargetContainer = "database-vault",
                RecommendedIptablesRule = "iptables -I DOCKER-USER -s 172.17.0.2 -d 172.17.0.3 -j DROP"
            }
        };

        // Act
        var audit = await _auditor.AuditIptablesChainsAsync(breaches);

        // Assert
        Assert.Contains(audit.SecurityWarnings, w => w.Contains("attacker-c2 -> database-vault"));
        Assert.Contains(audit.RecommendedFixes, r => r.Contains("-s 172.17.0.2 -d 172.17.0.3 -j DROP"));
    }
}
