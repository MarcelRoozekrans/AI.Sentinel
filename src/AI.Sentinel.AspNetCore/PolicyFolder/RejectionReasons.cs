namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>Why a configuration was refused. The names are written to the audit log, so they carry no file content.</summary>
internal static class RejectionReasons
{
    public const string InvalidNodeConfiguration = "invalid_node_configuration";
    public const string NoPolicy = "no_policy";
    public const string UnknownBundle = "unknown_bundle";
    public const string WrongPackage = "wrong_package";
    public const string AllowRuleBelowOrganisation = "allow_rule_below_organisation";
    public const string OutsideBuiltin = "outside_builtin";
    public const string DoesNotCompile = "does_not_compile";
    public const string InvalidFolder = "invalid_folder";
}
