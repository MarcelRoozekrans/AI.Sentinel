namespace AI.Sentinel.Mcp;

/// <summary>Detector preset for the MCP proxy pipeline.</summary>
public enum McpDetectorPreset
{
    /// <summary>
    /// 9 regex/pattern-based security detectors. Default. Low-false-positive on
    /// structured tool arguments and results.
    /// </summary>
    Security,

    /// <summary>
    /// Everything <c>AddAISentinel</c> registers. Opt-in via
    /// <c>SENTINEL_MCP_DETECTORS=all</c> — expect more false positives on
    /// structured data.
    /// </summary>
    All,
}
