<#
.SYNOPSIS
  Measures cold-start latency of a hook CLI binary over N fresh invocations.

.DESCRIPTION
  Launches the specified binary N times with a clean user-prompt-submit payload
  on stdin, times each process from launch to exit via Stopwatch, and reports
  mean / p50 / p95 / min / max in milliseconds. Intended for comparing the
  framework-dependent dotnet-tool entry point against the Native AOT binary.

  Each invocation is a separate process with no caching between runs — this is
  the metric that matters for hook-style workloads where the agent launches the
  binary per tool call.

.PARAMETER Binary
  One or more paths to CLI binaries to benchmark. Pass two to compare.

.PARAMETER Runs
  Number of invocations per binary. Default: 50. Use 100+ for tighter p95.

.PARAMETER Event
  The hook event argument to pass. Default: 'user-prompt-submit' (Claude Code
  variant). Use 'user-prompt-submitted' for Copilot.

.EXAMPLE
  ./tools/cold-start-bench.ps1 `
    -Binary ./aot-out-claude/AI.Sentinel.ClaudeCode.Cli.exe `
    -Binary "$env:USERPROFILE/.dotnet/tools/sentinel-hook.exe" `
    -Runs 100

.EXAMPLE
  ./tools/cold-start-bench.ps1 -Binary ./aot-out-claude/AI.Sentinel.ClaudeCode.Cli.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string[]]$Binary,

    [int]$Runs = 50,

    [string]$Event = 'user-prompt-submit'
)

$ErrorActionPreference = 'Stop'

foreach ($path in $Binary) {
    if (-not (Test-Path $path)) {
        throw "Binary not found: $path"
    }
}

$payload = '{"session_id":"bench","prompt":"hello from cold-start bench"}'

function Measure-ColdStart {
    param([string]$Path, [int]$Count, [string]$EventArg, [string]$Payload)

    # Warm up the OS file cache. Stdin must be piped — the binary blocks on
    # Console.In.ReadToEndAsync() otherwise.
    $Payload | & $Path $EventArg *> $null 2>&1 | Out-Null

    $samples = [double[]]::new($Count)
    for ($i = 0; $i -lt $Count; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $Payload | & $Path $EventArg *> $null 2>&1 | Out-Null
        $sw.Stop()
        $samples[$i] = $sw.Elapsed.TotalMilliseconds
    }
    return $samples
}

function Summarise {
    param([double[]]$Samples)

    $sorted = $Samples | Sort-Object
    $n = $sorted.Count
    return [pscustomobject]@{
        Runs    = $n
        MeanMs  = [math]::Round(($sorted | Measure-Object -Average).Average, 2)
        P50Ms   = [math]::Round($sorted[[int][math]::Floor(0.50 * ($n - 1))], 2)
        P95Ms   = [math]::Round($sorted[[int][math]::Floor(0.95 * ($n - 1))], 2)
        MinMs   = [math]::Round($sorted[0], 2)
        MaxMs   = [math]::Round($sorted[-1], 2)
    }
}

$results = foreach ($path in $Binary) {
    $name = Split-Path -Leaf $path
    Write-Host "Benchmarking $name ($Runs runs)..." -ForegroundColor Cyan
    $samples = Measure-ColdStart -Path $path -Count $Runs -EventArg $Event -Payload $payload
    $summary = Summarise -Samples $samples
    [pscustomobject]@{
        Binary = $name
        Runs   = $summary.Runs
        MeanMs = $summary.MeanMs
        P50Ms  = $summary.P50Ms
        P95Ms  = $summary.P95Ms
        MinMs  = $summary.MinMs
        MaxMs  = $summary.MaxMs
    }
}

$results | Format-Table -AutoSize
