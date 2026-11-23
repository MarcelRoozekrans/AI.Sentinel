using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>
/// The builtins the host runs for a module. The OPA wasm library carries most builtins itself and imports the rest from
/// the host. This host runs <c>sprintf</c>, which any policy that formats a reason needs, and no other import: a call of
/// another denies and names it (#654). The imports found by the spike and still missing are <c>crypto.sha256</c>,
/// <c>net.cidr_contains_matches</c>, <c>regex.find_n</c>, <c>regex.replace</c>, <c>semver.compare</c>,
/// <c>time.now_ns</c>, <c>units.parse_bytes</c>, <c>urlquery.decode</c>, <c>uuid.rfc4122</c> and <c>yaml.unmarshal</c>.
/// </summary>
internal static class HostBuiltins
{
    /// <summary>True when the host runs the builtin <paramref name="name"/>.</summary>
    public static bool IsImplemented(string name) => string.Equals(name, "sprintf", StringComparison.Ordinal);

    /// <summary>Runs <c>sprintf</c> on the JSON of its two arguments, a format string and an array. Returns the JSON of the
    /// result, or <see langword="null"/> when an argument has the wrong type, which is undefined in Rego.</summary>
    public static string? Sprintf(string formatJson, string argsJson)
    {
        using var format = JsonDocument.Parse(formatJson);
        using var args = JsonDocument.Parse(argsJson);
        if (format.RootElement.ValueKind != JsonValueKind.String || args.RootElement.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var text = Format(format.RootElement.GetString()!, args.RootElement.EnumerateArray().ToList());
        return Quote(text);
    }

    private static string Format(string format, List<JsonElement> args)
    {
        var sb = new StringBuilder();
        var next = 0;
        for (var i = 0; i < format.Length; i++)
        {
            if (format[i] != '%')
            {
                sb.Append(format[i]);
                continue;
            }

            i++;
            var spec = ReadSpec(format, ref i);
            if (spec.Verb == '%')
            {
                sb.Append('%');
            }
            else if (spec.Verb == '\0')
            {
                sb.Append("%!(NOVERB)");
            }
            else if (next >= args.Count)
            {
                sb.Append("%!").Append(spec.Verb).Append("(MISSING)");
            }
            else
            {
                sb.Append(Pad(Verb(spec, args[next++]), spec));
            }
        }

        if (next < args.Count)
        {
            sb.Append("%!(EXTRA ").AppendJoin(", ", args.Skip(next).Select(Describe)).Append(')');
        }

        return sb.ToString();
    }

    private sealed record Spec(bool Minus, bool Plus, bool Space, bool Zero, int Width, int Precision, char Verb);

    private static Spec ReadSpec(string f, ref int i)
    {
        bool minus = false, plus = false, space = false, zero = false;
        for (; i < f.Length && f[i] is '-' or '+' or ' ' or '0' or '#'; i++)
        {
            minus |= f[i] == '-';
            plus |= f[i] == '+';
            space |= f[i] == ' ';
            zero |= f[i] == '0';
        }

        var width = ReadNumber(f, ref i);
        var precision = -1;
        if (i < f.Length && f[i] == '.')
        {
            i++;
            precision = Math.Max(ReadNumber(f, ref i), 0);
        }

        return new Spec(minus, plus, space, zero, Math.Max(width, 0), precision, i < f.Length ? f[i] : '\0');
    }

    private static int ReadNumber(string f, ref int i)
    {
        var n = 0;
        var any = false;
        for (; i < f.Length && char.IsAsciiDigit(f[i]); i++)
        {
            n = Math.Min((n * 10) + (f[i] - '0'), 10_000);
            any = true;
        }

        return any ? n : -1;
    }

    private static string Pad(string text, Spec spec)
    {
        if (text.Length >= spec.Width)
        {
            return text;
        }

        if (spec.Minus)
        {
            return text.PadRight(spec.Width);
        }

        if (spec.Zero && spec.Verb is 'd' or 'f' or 'F' or 'e' or 'E' or 'g' or 'G' or 'x' or 'X' or 'o' or 'b')
        {
            var sign = text.Length > 0 && text[0] is '-' or '+' or ' ' ? text[..1] : string.Empty;
            return sign + text[sign.Length..].PadLeft(spec.Width - sign.Length, '0');
        }

        return text.PadLeft(spec.Width);
    }

    private static string Verb(Spec spec, JsonElement arg) => spec.Verb switch
    {
        's' or 'v' => Truncate(Value(arg), spec),
        'q' => Quote(Value(arg)),
        't' => arg.ValueKind is JsonValueKind.True or JsonValueKind.False ? Value(arg) : Bad(spec, arg),
        'd' => Integer(arg, spec, 10),
        'x' => arg.ValueKind == JsonValueKind.String ? Convert.ToHexStringLower(Encoding.UTF8.GetBytes(arg.GetString()!)) : Integer(arg, spec, 16),
        'X' => arg.ValueKind == JsonValueKind.String ? Convert.ToHexString(Encoding.UTF8.GetBytes(arg.GetString()!)) : Integer(arg, spec, 16).ToUpperInvariant(),
        'o' => Integer(arg, spec, 8),
        'b' => Integer(arg, spec, 2),
        'f' or 'F' or 'e' or 'E' or 'g' or 'G' => Float(arg, spec),
        _ => Bad(spec, arg),
    };

    private static string Truncate(string text, Spec spec) => spec.Precision >= 0 && spec.Precision < text.Length ? text[..spec.Precision] : text;

    private static string Integer(JsonElement arg, Spec spec, int radix)
    {
        if (arg.ValueKind != JsonValueKind.Number || !arg.TryGetInt64(out var n))
        {
            return Bad(spec, arg);
        }

        var digits = radix switch
        {
            10 => Math.Abs((decimal)n).ToString(CultureInfo.InvariantCulture),
            _ => Convert.ToString(Math.Abs(n), radix),
        };
        return Sign(n < 0, spec) + digits;
    }

    private static string Float(JsonElement arg, Spec spec)
    {
        if (arg.ValueKind != JsonValueKind.Number)
        {
            return Bad(spec, arg);
        }

        var d = arg.GetDouble();
        var precision = spec.Precision < 0 ? 6 : spec.Precision;
        var body = spec.Verb switch
        {
            'f' or 'F' => Math.Abs(d).ToString("F" + precision.ToString(CultureInfo.InvariantCulture), CultureInfo.InvariantCulture),
            'e' => Math.Abs(d).ToString("0." + new string('0', precision) + "e+00", CultureInfo.InvariantCulture),
            'E' => Math.Abs(d).ToString("0." + new string('0', precision) + "E+00", CultureInfo.InvariantCulture),
            _ => spec.Precision < 0
                ? Math.Abs(d).ToString("R", CultureInfo.InvariantCulture)
                : Math.Abs(d).ToString("G" + precision.ToString(CultureInfo.InvariantCulture), CultureInfo.InvariantCulture),
        };
        return Sign(d < 0, spec) + body;
    }

    private static string Sign(bool negative, Spec spec) => negative ? "-" : spec.Plus ? "+" : spec.Space ? " " : string.Empty;

    private static string Bad(Spec spec, JsonElement arg) => $"%!{spec.Verb}({Describe(arg)})";

    private static string Describe(JsonElement arg) => arg.ValueKind switch
    {
        JsonValueKind.String => "string=" + arg.GetString(),
        JsonValueKind.Number => (arg.TryGetInt64(out _) ? "int=" : "float64=") + Value(arg),
        JsonValueKind.True or JsonValueKind.False => "bool=" + Value(arg),
        JsonValueKind.Null => "<nil>",
        _ => "value=" + Value(arg),
    };

    /// <summary>The text of a value: a string as it is, a number, a boolean or null in their JSON form, and an array or an
    /// object in the form Rego prints it, <c>["a", 1]</c> and <c>{"k": true}</c> with the keys in order.</summary>
    private static string Value(JsonElement e)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.String:
                return e.GetString()!;
            case JsonValueKind.Number:
                return e.TryGetInt64(out var l) ? l.ToString(CultureInfo.InvariantCulture) : e.GetDouble().ToString("R", CultureInfo.InvariantCulture);
            case JsonValueKind.True:
                return "true";
            case JsonValueKind.False:
                return "false";
            case JsonValueKind.Array:
                return "[" + string.Join(", ", e.EnumerateArray().Select(Nested)) + "]";
            case JsonValueKind.Object:
                return "{" + string.Join(", ", e.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal).Select(p => Quote(p.Name) + ": " + Nested(p.Value))) + "}";
            default:
                return "null";
        }
    }

    private static string Nested(JsonElement e) => e.ValueKind == JsonValueKind.String ? Quote(e.GetString()!) : Value(e);

    /// <summary>The string as a JSON string literal. Only what JSON requires is escaped, so a quote is <c>\"</c> and text outside
    /// ASCII stays as it is; the literal is the result of <c>sprintf</c> as well as what <c>%q</c> prints.</summary>
    private static string Quote(string s)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            writer.WriteStringValue(s);
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }
}
