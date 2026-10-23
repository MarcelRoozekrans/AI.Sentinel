namespace AI.Sentinel.ClaudeCode;

/// <summary>Which detectors the MCP proxy runs; the sets are in <see cref="DetectorPresets"/>.</summary>
internal enum DetectorPreset
{
    /// <summary>
    /// 14 security detectors and the 4 Art. 5 compliance detectors. Default. Chosen for a low
    /// false-positive rate on structured tool arguments and results.
    /// </summary>
    Security,

    /// <summary>
    /// Everything <c>AddAISentinel</c> registers, including the response-quality detectors that judge a
    /// model's reply. Opt-in via <c>SENTINEL_MCP_DETECTORS=all</c>; expect more false positives on
    /// structured data.
    /// </summary>
    All,
}
