namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>What one pass over the policy folder came to.</summary>
internal enum PassResult
{
    /// <summary>A new complete version was validated and is now in force.</summary>
    Published,

    /// <summary>The folder holds the version that is already in force.</summary>
    Unchanged,

    /// <summary>The version failed validation. It is not published and the last good one stays in force.</summary>
    Rejected,

    /// <summary>The read or the compile failed, or the folder changed during the pass. Nothing was published; try again.</summary>
    Retry,
}
