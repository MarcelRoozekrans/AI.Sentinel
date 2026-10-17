namespace AI.Sentinel.Mcp;

/// <summary>Detector preset for the MCP proxy pipeline.</summary>
internal enum McpDetectorPreset
{
    /// <summary>
    /// 13 security detectors and the 4 Art. 5 compliance detectors. Default. Chosen for a low
    /// false-positive rate on structured tool arguments and results.
    /// </summary>
    Security,

    /// <summary>
    /// Everything <c>AddAISentinel</c> registers. Opt-in via
    /// <c>SENTINEL_MCP_DETECTORS=all</c> — expect more false positives on
    /// structured data.
    /// </summary>
    All,
}
