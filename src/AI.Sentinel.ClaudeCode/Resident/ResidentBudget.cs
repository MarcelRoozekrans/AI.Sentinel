using System.Diagnostics;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// The time one hook call may spend waiting for the resident process, shared by every exchange of that call: the folder policy and the
/// profiles of the organisation and the node (#729). The time each exchange takes is added up, an exchange gets what is left, and after
/// one gets no answer, or the budget is spent, the resident process is not asked again in that call. A thrown error is no silence: it
/// passes through, and the time it took still counts.
/// </summary>
/// <param name="total">The budget of the call, <see cref="ResidentSettings.Budget"/>.</param>
internal sealed class ResidentBudget(TimeSpan total)
{
    private bool _missed;
    private TimeSpan _spent;

    /// <summary>The answer of <paramref name="exchange"/>, which is given the time that is left; <see langword="null"/> without asking
    /// when nothing is left or an earlier exchange got no answer.</summary>
    public T? Spend<T>(Func<TimeSpan, T?> exchange)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(exchange);
        if (_missed)
        {
            return null;
        }

        var left = total - _spent;
        if (left <= TimeSpan.Zero)
        {
            _missed = true;
            return null;
        }

        var started = Stopwatch.GetTimestamp();
        try
        {
            var answer = exchange(left);
            _missed = answer is null;
            return answer;
        }
        finally
        {
            _spent += Stopwatch.GetElapsedTime(started);
        }
    }
}
