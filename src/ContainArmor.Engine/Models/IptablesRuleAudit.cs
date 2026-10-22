namespace ContainArmor.Engine.Models;

public class IptablesRule
{
    public int LineNumber { get; set; }
    public string Table { get; set; } = "filter";
    public string Chain { get; set; } = "DOCKER-USER";
    public string Target { get; set; } = "RETURN"; // ACCEPT, DROP, REJECT, RETURN
    public string Protocol { get; set; } = "all";
    public string InInterface { get; set; } = "*";
    public string OutInterface { get; set; } = "*";
    public string Source { get; set; } = "0.0.0.0/0";
    public string Destination { get; set; } = "0.0.0.0/0";
    public string ExtraOptions { get; set; } = string.Empty;
    public RuleStatus Status { get; set; } = RuleStatus.Compliant;
    public string AnalysisNote { get; set; } = string.Empty;
    public bool IsRemediationRule { get; set; }
}

public class IptablesChainAudit
{
    public string ChainName { get; set; } = string.Empty;
    public string Policy { get; set; } = "ACCEPT";
    public List<IptablesRule> Rules { get; set; } = [];
    public bool HasPromiscuousAccept { get; set; }
    public bool MissingExplicitDrop { get; set; }
    public bool HasMisorderedDrop { get; set; }
    public SeverityLevel VulnerabilitySeverity { get; set; } = SeverityLevel.Info;
    public string RemediationSuggestion { get; set; } = string.Empty;
}

public class IptablesFirewallAudit
{
    public DateTime AuditedAt { get; set; } = DateTime.UtcNow;
    public string FirewallEngine { get; set; } = "iptables (Linux Netfilter)";
    public List<IptablesChainAudit> Chains { get; set; } = [];
    public int TotalRulesAudited { get; set; }
    public int HighRiskRulesCount { get; set; }
    public bool DockerUserChainProperlySecured { get; set; }
    public List<string> SecurityWarnings { get; set; } = [];
    public List<string> RecommendedFixes { get; set; } = [];
}
