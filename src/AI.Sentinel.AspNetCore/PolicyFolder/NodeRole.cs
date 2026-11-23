namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>The three roles of ADR-109, from the lowest: everyone else, a team lead on a team, an administrator on the organisation.</summary>
internal enum NodeRole
{
    Developer = 0,
    TeamLead = 1,
    Administrator = 2,
}
