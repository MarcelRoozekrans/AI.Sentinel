using RegoAot;

if (args.Contains("--once", StringComparer.Ordinal))
{
    return Measure.Once(args);
}

if (args.Contains("--measure", StringComparer.Ordinal))
{
    return Measure.Run(args);
}

return Check.Run(args);
