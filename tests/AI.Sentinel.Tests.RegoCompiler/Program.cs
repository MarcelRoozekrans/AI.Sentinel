using AI.Sentinel.ClaudeCode.Policy.Rego;

// Usage: AI.Sentinel.Tests.RegoCompiler <policy-folder> <output-wasm> [--unrestricted]
// Compiles every .rego file of the folder, with the host rules, to one WebAssembly module and writes it to <output-wasm>.
// With --unrestricted the compiler is not given the capabilities document, so a builtin that reaches outside the process
// compiles. Exit code 0 on success, 3 when the policy does not compile (the compiler message is on stderr), 2 on bad usage.
if (args.Length is < 2 or > 3)
{
    await Console.Error.WriteLineAsync("usage: <policy-folder> <output-wasm> [--unrestricted]");
    return 2;
}

try
{
    var wasm = new InteropRegoCompiler().CompileWasm(PolicySources.Load(args[0]), restrictBuiltins: args.Length == 2);
    await File.WriteAllBytesAsync(args[1], wasm);
    return 0;
}
catch (RegoCompileException e)
{
    await Console.Error.WriteLineAsync(e.Message);
    return 3;
}
