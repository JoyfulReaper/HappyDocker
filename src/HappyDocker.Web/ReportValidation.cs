namespace HappyDocker.Web;

public static class ReportValidation
{
    public const int MaximumBytes = AgentReportValidation.MaximumBytes;
    public const int MaximumFindings = AgentReportValidation.MaximumFindings;
    public static string? Validate(AgentReport report, DateTimeOffset now) => AgentReportValidation.Validate(report, now);
}
