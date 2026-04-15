namespace AI.Sentinel.Detection;

/// <summary>
/// Detectors that implement this interface opt into a second-pass LLM analysis
/// when their rule-based result is Medium or higher AND an EscalationClient is configured.
/// </summary>
public interface ILlmEscalatingDetector : IDetector { }
