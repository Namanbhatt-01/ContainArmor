namespace ContainArmor.Engine.Models;

public class SecurityFinding
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string RuleId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public SeverityLevel Severity { get; set; } = SeverityLevel.Medium;
    public RiskCategory Category { get; set; } = RiskCategory.PrivilegeEscalation;
    public string Description { get; set; } = string.Empty;
    public string Impact { get; set; } = string.Empty;
    public string Remediation { get; set; } = string.Empty;
    public string CisBenchmark { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}
