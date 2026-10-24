namespace AI.Sentinel.ClaudeCode;

/// <summary>Which detectors the hook CLIs and the MCP proxy run. Shared by <c>sentinel-hook</c>,
/// <c>sentinel-copilot-hook</c> and <c>sentinel-mcp</c>; the sets are in <see cref="DetectorPresets"/>.</summary>
internal enum DetectorPreset
{
    /// <summary>
    /// 16 security detectors and the 4 Art. 5 compliance detectors. Default. Chosen for a low
    /// false-positive rate on prompts, tool arguments and tool results, which is all these hosts scan.
    /// </summary>
    Security,

    /// <summary>
    /// Everything <c>AddAISentinel</c> registers, including the response-quality detectors that judge a
    /// model's reply. Opt-in via <c>SENTINEL_HOOK_DETECTORS=all</c> or <c>SENTINEL_MCP_DETECTORS=all</c>;
    /// expect more false positives on tool output.
    /// </summary>
    All,
}
