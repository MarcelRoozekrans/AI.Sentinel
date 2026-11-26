using System.Buffers;
using System.Globalization;
using System.Numerics;
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
    /// <remarks>OPA passes the arguments to Go's <c>fmt.Sprintf</c>, and so does this, with Go's verbs, flags, width,
    /// precision, <c>*</c> widths and precisions, <c>%[n]</c> indexes and error markers. Not carried over: <c>%w</c>, which
    /// Go reserves for errors.</remarks>
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
        var values = args.ConvertAll(Arg.From);
        var sb = new StringBuilder();
        var cursor = new Cursor(values);
        for (var i = 0; i < format.Length; i++)
        {
            if (format[i] != '%')
            {
                sb.Append(format[i]);
                continue;
            }

            i++;
            var spec = ReadSpec(format, ref i, cursor, sb);
            if (spec.Verb == 'v')
            {
                // Go reads %+v and %#v as forms of their own, and neither one signs or prefixes a value of these types.
                spec = spec with { Plus = false, Sharp = false, PlusV = spec.Plus, Quoted = spec.Sharp };
            }

            if (spec.Verb == '\0')
            {
                sb.Append("%!(NOVERB)");
            }
            else if (spec.Verb == '%')
            {
                sb.Append('%');
            }
            else if (!spec.GoodIndex)
            {
                sb.Append("%!").Append(spec.Verb).Append("(BADINDEX)");
            }
            else if (cursor.Next >= values.Count)
            {
                sb.Append("%!").Append(spec.Verb).Append("(MISSING)");
            }
            else
            {
                sb.Append(Verb(spec, values[cursor.Next++]));
            }
        }

        if (!cursor.Reordered && cursor.Next < values.Count)
        {
            sb.Append("%!(EXTRA ").AppendJoin(", ", values.Skip(cursor.Next).Select(a => a.ExtraType + "=" + Verb(Spec.Plain, a))).Append(')');
        }

        return sb.ToString();
    }

    /// <summary>The next argument, and whether a <c>%[n]</c> index was seen, which turns the EXTRA marker off.</summary>
    private sealed class Cursor(List<Arg> values)
    {
        public List<Arg> Values { get; } = values;

        public int Count => Values.Count;

        public int Next { get; set; }

        public bool Reordered { get; set; }
    }

    /// <summary>A <c>sprintf</c> argument the way OPA hands it to Go's <c>fmt</c>: a number that is an integer as an int64, or
    /// as a big.Int when it does not fit one, any other number as a float64, a string as it is, and a boolean, null, array or
    /// object as the string Rego prints for it.</summary>
    private sealed record Arg(char Kind, BigInteger Integer, double Float, string Text)
    {
        public static Arg From(JsonElement e)
        {
            if (e.ValueKind == JsonValueKind.Number)
            {
                var raw = e.GetRawText();
                if (BigInteger.TryParse(raw, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var n))
                {
                    return new Arg('i', n, 0, raw);
                }

                // A number beyond the range of a float64 is no float to OPA, which hands Go its text as a string.
                return double.IsFinite(e.GetDouble()) ? new Arg('f', BigInteger.Zero, e.GetDouble(), raw) : new Arg('s', BigInteger.Zero, 0, raw);
            }

            return new Arg('s', BigInteger.Zero, 0, Value(e));
        }

        /// <summary>An integer that does not fit an int64, which Go formats as a big.Int.</summary>
        public bool IsBig => Kind == 'i' && (Integer < long.MinValue || Integer > long.MaxValue);

        /// <summary>The type name in a bad-verb marker.</summary>
        public string Type => Kind switch { 'i' => "int64", 'f' => "float64", _ => "string" };

        /// <summary>The type name in the EXTRA marker, which Go takes from reflection.</summary>
        public string ExtraType => IsBig ? "*big.Int" : Type;
    }

    private sealed record Spec(bool Minus, bool Plus, bool Space, bool Zero, bool Sharp, int Width, int Precision, char Verb, bool GoodIndex = true)
    {
        public static readonly Spec Plain = new(false, false, false, false, false, 0, -1, 'v');

        /// <summary>%#v: a string prints as a Go string literal.</summary>
        public bool Quoted { get; init; }

        /// <summary>%+v: only a big.Int, which formats itself, still prints the plus sign.</summary>
        public bool PlusV { get; init; }
    }

    // Go's order: flags, an index, a width, then a dot with an index and a precision, and an index before the verb when
    // none came yet. An index right in front of a width or a dot, as in %[2]5d, is bad.
    private static Spec ReadSpec(string f, ref int i, Cursor cursor, StringBuilder sb)
    {
        bool minus = false, plus = false, space = false, zero = false, sharp = false;
        for (; i < f.Length && f[i] is '-' or '+' or ' ' or '0' or '#'; i++)
        {
            minus |= f[i] == '-';
            plus |= f[i] == '+';
            space |= f[i] == ' ';
            zero |= f[i] == '0';
            sharp |= f[i] == '#';
        }

        var good = true;
        var afterIndex = TakeIndex(f, ref i, cursor, ref good);
        int width;
        if (i < f.Length && f[i] == '*')
        {
            // The width is an argument; a negative one left-justifies, and one that is not a small integer is BADWIDTH.
            i++;
            width = ArgumentNumber(cursor, sb, precision: false);
            if (width < 0)
            {
                width = -width;
                minus = true;
                zero = false;
            }

            afterIndex = false;
        }
        else
        {
            width = ReadNumber(f, ref i);
            good &= !(afterIndex && width >= 0);
        }

        var precision = -1;
        if (i + 1 < f.Length && f[i] == '.')
        {
            i++;
            good &= !afterIndex;
            afterIndex = TakeIndex(f, ref i, cursor, ref good);
            if (i < f.Length && f[i] == '*')
            {
                i++;
                precision = ArgumentNumber(cursor, sb, precision: true);
                afterIndex = false;
            }
            else
            {
                precision = Math.Max(ReadNumber(f, ref i), 0);
            }
        }

        if (!afterIndex)
        {
            TakeIndex(f, ref i, cursor, ref good);
        }

        return new Spec(minus, plus, space, zero, sharp, Math.Max(width, 0), precision, i < f.Length ? f[i] : '\0', good);
    }

    // Go's intFromArg for a * width or precision: the next argument, which is used up even when it is no good. Anything but
    // an integer of at most a million in size writes the marker and is -1, which a precision reads as absent; a width reads
    // it as none too, and a negative precision is just as bad.
    private static int ArgumentNumber(Cursor cursor, StringBuilder sb, bool precision)
    {
        var arg = cursor.Next < cursor.Count ? cursor.Values[cursor.Next++] : null;
        if (arg is { Kind: 'i', IsBig: false } && BigInteger.Abs(arg.Integer) <= 1_000_000 && (arg.Integer >= 0 || !precision))
        {
            return (int)arg.Integer;
        }

        sb.Append(precision ? "%!(BADPREC)" : "%!(BADWIDTH)");
        return precision ? -1 : 0;
    }

    // A [n] at i: the n-th argument becomes the next one. A number outside the arguments, or a bracket that holds no
    // number, is bad. True when a bracket with a number was read.
    private static bool TakeIndex(string f, ref int i, Cursor cursor, ref bool good)
    {
        if (i >= f.Length || f[i] != '[')
        {
            return false;
        }

        cursor.Reordered = true;
        var close = f.IndexOf(']', i + 1);
        if (f.Length - i < 3 || close < 0)
        {
            i++;
            good = false;
            return false;
        }

        var digits = f.AsSpan(i + 1, close - i - 1);
        i = close + 1;
        if (digits.Length is 0 or > 6 || !int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out var n))
        {
            good = false;
            return false;
        }

        if (n >= 1 && n <= cursor.Count)
        {
            cursor.Next = n - 1;
        }
        else
        {
            good = false;
        }

        return true;
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

    // One verb applied to one argument, padded to the width, as Go's fmt does for the verbs of the argument's type. A verb
    // the type has no meaning for gives Go's bad-verb marker, which prints the argument with %v and the same flags.
    private static string Verb(Spec spec, Arg arg) => (arg.Kind, spec.Verb) switch
    {
        (_, 'T') => Pad(Truncate(arg.ExtraType, spec.Precision), spec, zeroAfterSign: false), // the Go type name, formatted as a string
        ('i', 'd' or 'v' or 's') when spec.Verb != 's' || arg.IsBig => Integer(arg.Integer, spec with { Plus = spec.Plus || (spec.PlusV && arg.IsBig) }, 10, arg.IsBig),
        ('i', 'b') => Integer(arg.Integer, spec, 2, arg.IsBig),
        ('i', 'o') => Integer(arg.Integer, spec, 8, arg.IsBig),
        ('i', 'O') => Integer(arg.Integer, spec with { Sharp = spec.Sharp && !arg.IsBig }, 8, arg.IsBig), // a big.Int ignores # for %O
        ('i', 'x' or 'X') => Integer(arg.Integer, spec, 16, arg.IsBig),
        ('i', 'c') when !arg.IsBig => Pad(ToRune(arg.Integer).ToString(), spec, zeroAfterSign: false),
        ('i', 'q') when !arg.IsBig => Pad(GoQuote(ToRune(arg.Integer).ToString(), spec.Plus, '\''), spec, zeroAfterSign: false),
        ('i', 'U') when !arg.IsBig => Pad(Unicode(arg.Integer, spec), spec with { Zero = false }, zeroAfterSign: false),
        ('f', 'v' or 'b' or 'e' or 'E' or 'f' or 'F' or 'g' or 'G' or 'x' or 'X') => Float(arg.Float, spec),
        ('s', 'v') when spec.Quoted => Pad(GoQuote(Truncate(arg.Text, spec.Precision), ascii: false, '"'), spec, zeroAfterSign: false),
        ('s', 's' or 'v') => Pad(Truncate(arg.Text, spec.Precision), spec, zeroAfterSign: false),
        ('s', 'q') => Pad(Quoted(Truncate(arg.Text, spec.Precision), spec), spec, zeroAfterSign: false),
        ('s', 'x' or 'X') => Pad(Hex(arg.Text, spec), spec, zeroAfterSign: false),
        // A big.Int formats itself, and prints its bad-verb marker without the flags.
        ('i', _) when arg.IsBig => $"%!{spec.Verb}(big.Int={arg.Integer.ToString(CultureInfo.InvariantCulture)})",
        _ => $"%!{spec.Verb}({arg.Type}={Verb(spec with { Verb = 'v' }, arg)})",
    };

    // Go's fmtInteger: the precision is a minimum number of digits, and without one the zero flag pads the digits to the
    // width; the # prefix and the sign come after that, and the rest of the width is spaces.
    // A big.Int formats itself: its zero padding counts the prefix in the width, where an int64 pads the digits alone.
    private static string Integer(BigInteger value, Spec spec, int radix, bool big)
    {
        var magnitude = BigInteger.Abs(value);
        if (spec.Precision == 0 && magnitude.IsZero)
        {
            return new string(' ', spec.Width); // Go prints nothing, not even a sign, for a zero with precision 0
        }

        var digits = ToRadix(magnitude, radix);
        if (spec.Verb == 'X')
        {
            digits = digits.ToUpperInvariant();
        }

        var sign = Sign(value.Sign < 0, spec);
        var minimum = spec.Precision >= 0 ? spec.Precision
            : spec.Zero && !spec.Minus && spec.Width > 0 ? spec.Width - sign.Length - (big ? Prefix(digits, spec, radix, big).Length : 0)
            : 0;
        digits = digits.PadLeft(minimum, '0');
        var prefix = Prefix(digits, spec, radix, big);
        return Pad(sign + prefix + digits, spec with { Zero = false }, zeroAfterSign: false);
    }

    // The # prefix of a number: an octal int64 starts with a 0 of its own already when the padding gave it one. %O always
    // has 0o.
    private static string Prefix(string digits, Spec spec, int radix, bool big)
    {
        var prefix = !spec.Sharp ? string.Empty
            : radix switch
            {
                2 => "0b",
                8 => !big && digits.StartsWith('0') ? string.Empty : "0",
                16 => spec.Verb == 'X' ? "0X" : "0x",
                _ => string.Empty,
            };
        return spec.Verb == 'O' ? "0o" + prefix : prefix;
    }

    // %c and %q of a number take it as a code point; one that is not a valid one is U+FFFD.
    private static Rune ToRune(BigInteger value) =>
        value >= 0 && value <= 0x10FFFF && Rune.IsValid((int)value) ? new Rune((int)value) : Rune.ReplacementChar;

    // %U: U+ and at least four hex digits, with # followed by the character in quotes when it is printable. A negative
    // number is its 64-bit two's complement, as Go converts it to an unsigned integer.
    private static string Unicode(BigInteger value, Spec spec)
    {
        var unsigned = value < 0 ? value + (BigInteger.One << 64) : value;
        var text = "U+" + ToRadix(unsigned, 16).ToUpperInvariant().PadLeft(Math.Max(spec.Precision, 4), '0');
        return spec.Sharp && unsigned <= 0x10FFFF && Rune.IsValid((int)unsigned) && IsPrint(new Rune((int)unsigned))
            ? text + " '" + new Rune((int)unsigned) + "'"
            : text;
    }

    private static string ToRadix(BigInteger magnitude, int radix)
    {
        if (radix == 10)
        {
            return magnitude.ToString(CultureInfo.InvariantCulture);
        }

        if (magnitude.IsZero)
        {
            return "0";
        }

        var sb = new StringBuilder();
        for (; !magnitude.IsZero; magnitude /= radix)
        {
            sb.Insert(0, "0123456789abcdef"[(int)(magnitude % radix)]);
        }

        return sb.ToString();
    }

    // Go's strconv formatting of a float64, rounded half to even on the exact binary value: %e and %f with six decimals by
    // default, %g and %v with the shortest digits that read back as the same value.
    private static string Float(double value, Spec spec)
    {
        var verb = spec.Verb == 'v' ? 'g' : spec.Verb;
        var magnitude = Math.Abs(value);
        string body;
        if (verb is 'b' or 'x' or 'X')
        {
            body = Binary(magnitude, verb, spec.Precision);
        }
        else if (verb is 'e' or 'E')
        {
            var precision = spec.Precision < 0 ? 6 : spec.Precision;
            var (digits, point) = Round(magnitude, significant: precision + 1);
            body = Exponent(digits, point, precision, verb);
        }
        else if (verb is 'f' or 'F')
        {
            var precision = spec.Precision < 0 ? 6 : spec.Precision;
            var (digits, point) = Round(magnitude, significant: null, decimals: precision);
            body = Fixed(digits, point, precision);
        }
        else
        {
            var (digits, point) = spec.Precision < 0 ? Shortest(magnitude) : Round(magnitude, significant: Math.Max(spec.Precision, 1));
            var limit = spec.Precision < 0 ? 6 : Math.Max(spec.Precision, 1);
            if (limit > digits.Length && digits.Length >= point && spec.Precision >= 0)
            {
                limit = digits.Length;
            }

            body = point - 1 < -4 || point - 1 >= limit
                ? Exponent(digits, point, Math.Max(digits.Length - 1, 0), verb == 'G' ? 'E' : 'e')
                : Fixed(digits, point, Math.Max(digits.Length - point, 0));
        }

        if (spec.Sharp && verb != 'b')
        {
            body = Alternate(body, verb, spec.Precision);
        }

        return Pad(Sign(double.IsNegative(value), spec) + body, spec, zeroAfterSign: true);
    }

    // Go's # flag for a float, ported as it is: the decimal point is always there, and %g, %v and %x keep their trailing
    // zeros up to the precision, six by default. Like Go, it counts the x of a hex float as a digit, and leaves %X out.
    private static string Alternate(string body, char verb, int precision)
    {
        var digits = verb is 'g' or 'G' or 'x' ? (precision < 0 ? 6 : precision) : 0;
        var number = body;
        var tail = string.Empty;
        var hasPoint = false;
        var sawNonzero = false;
        for (var i = 0; i < number.Length; i++)
        {
            var c = number[i];
            if (c == '.')
            {
                hasPoint = true;
            }
            else if (c is 'p' or 'P' || (c is 'e' or 'E' && verb is not ('x' or 'X')))
            {
                tail = number[i..];
                number = number[..i];
            }
            else
            {
                sawNonzero |= c != '0';
                digits -= sawNonzero ? 1 : 0;
            }
        }

        if (!hasPoint)
        {
            digits -= string.Equals(number, "0", StringComparison.Ordinal) ? 1 : 0;
            number += ".";
        }

        return number + new string('0', Math.Max(digits, 0)) + tail;
    }

    // %b of a float is the mantissa and the binary exponent, -ddddp±ddd, and %x the hex form -0x1.hhhp±dd, rounded to the
    // precision in hex digits, half to even.
    private static string Binary(double magnitude, char verb, int precision)
    {
        var bits = BitConverter.DoubleToInt64Bits(magnitude);
        var biased = (int)((bits >> 52) & 0x7FF);
        var mantissa = (ulong)(bits & 0xF_FFFF_FFFF_FFFFL);
        var exponent = biased == 0 ? -1022 : biased - 1023;
        if (biased != 0)
        {
            mantissa |= 1UL << 52;
        }

        if (verb == 'b')
        {
            var binaryExponent = exponent - 52;
            return mantissa.ToString(CultureInfo.InvariantCulture) + "p" + (binaryExponent >= 0 ? "+" : string.Empty) + binaryExponent.ToString(CultureInfo.InvariantCulture);
        }

        return Hex(mantissa, exponent, verb, precision);
    }

    private static string Hex(ulong mantissa, int exponent, char verb, int precision)
    {
        if (mantissa == 0)
        {
            exponent = 0;
        }

        mantissa <<= 8;
        while (mantissa != 0 && (mantissa & (1UL << 60)) == 0)
        {
            mantissa <<= 1;
            exponent--;
        }

        if (precision is >= 0 and < 15)
        {
            var shift = precision * 4;
            var extra = (mantissa << shift) & ((1UL << 60) - 1);
            mantissa >>= 60 - shift;
            if ((extra | (mantissa & 1)) > 1UL << 59)
            {
                mantissa++;
            }

            mantissa <<= 60 - shift;
            if ((mantissa & (1UL << 61)) != 0)
            {
                mantissa >>= 1;
                exponent++;
            }
        }

        var hex = verb == 'X' ? "0123456789ABCDEF" : "0123456789abcdef";
        var sb = new StringBuilder().Append('0').Append(verb).Append((char)('0' + (int)((mantissa >> 60) & 1)));
        mantissa <<= 4;
        if ((precision < 0 && mantissa != 0) || precision > 0)
        {
            sb.Append('.');
            for (var i = 0; precision < 0 ? mantissa != 0 : i < precision; i++)
            {
                sb.Append(hex[(int)((mantissa >> 60) & 15)]);
                mantissa <<= 4;
            }
        }

        return sb.Append(verb == 'X' ? 'P' : 'p').Append(exponent < 0 ? '-' : '+')
            .Append(Math.Abs(exponent).ToString("00", CultureInfo.InvariantCulture)).ToString();
    }

    // The digits of the value without leading or trailing zeros, and where the decimal point goes: value = 0.digits * 10^point.
    private static (string Digits, int Point) Shortest(double magnitude)
    {
        var roundTrip = magnitude.ToString("R", CultureInfo.InvariantCulture);
        var e = roundTrip.IndexOf('E', StringComparison.Ordinal);
        var mantissa = e < 0 ? roundTrip : roundTrip[..e];
        var exponent = e < 0 ? 0 : int.Parse(roundTrip.AsSpan(e + 1), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
        var dot = mantissa.IndexOf('.', StringComparison.Ordinal);
        var point = (dot < 0 ? mantissa.Length : dot) + exponent;
        return Trim(mantissa.Replace(".", string.Empty, StringComparison.Ordinal), point);
    }

    // Rounds half to even to the given number of significant digits, or of decimals when significant is null.
    private static (string Digits, int Point) Round(double magnitude, int? significant, int decimals = 0)
    {
        var bits = BitConverter.DoubleToInt64Bits(magnitude);
        var biased = (int)((bits >> 52) & 0x7FF);
        var fraction = bits & 0xF_FFFF_FFFF_FFFFL;
        var mantissa = new BigInteger(biased == 0 ? fraction : fraction | (1L << 52));
        var exponent = biased == 0 ? -1074 : biased - 1075;

        // magnitude = mantissa * 2^exponent = exact * 10^scale
        var exact = exponent >= 0 ? mantissa << exponent : mantissa * BigInteger.Pow(5, -exponent);
        var scale = Math.Min(exponent, 0);
        var all = exact.IsZero ? string.Empty : exact.ToString(CultureInfo.InvariantCulture);
        var point = all.Length + scale;
        var keep = significant ?? (point + decimals);
        if (keep >= all.Length)
        {
            return Trim(all, point);
        }

        if (keep < 0)
        {
            return (string.Empty, 0);
        }

        var head = keep == 0 ? BigInteger.Zero : BigInteger.Parse(all.AsSpan(0, keep), NumberStyles.None, CultureInfo.InvariantCulture);
        var first = all[keep];
        var restZero = all.AsSpan(keep + 1).IndexOfAnyExcept('0') < 0;
        if (first > '5' || (first == '5' && (!restZero || !head.IsEven)))
        {
            head += 1;
        }

        var rounded = head.IsZero ? string.Empty : head.ToString(CultureInfo.InvariantCulture);
        return Trim(rounded, point + (rounded.Length - keep));
    }

    private static (string Digits, int Point) Trim(string digits, int point)
    {
        var lead = digits.Length - digits.TrimStart('0').Length;
        digits = digits[lead..].TrimEnd('0');
        return digits.Length == 0 ? (string.Empty, 0) : (digits, point - lead);
    }

    private static char DigitAt(string digits, int i) => i >= 0 && i < digits.Length ? digits[i] : '0';

    private static string Exponent(string digits, int point, int decimals, char e)
    {
        var sb = new StringBuilder().Append(DigitAt(digits, 0));
        if (decimals > 0)
        {
            sb.Append('.');
            for (var i = 1; i <= decimals; i++)
            {
                sb.Append(DigitAt(digits, i));
            }
        }

        var exponent = digits.Length == 0 ? 0 : point - 1;
        return sb.Append(e).Append(exponent < 0 ? '-' : '+').Append(Math.Abs(exponent).ToString("00", CultureInfo.InvariantCulture)).ToString();
    }

    private static string Fixed(string digits, int point, int decimals)
    {
        var sb = new StringBuilder();
        if (point <= 0)
        {
            sb.Append('0');
        }

        for (var i = 0; i < point; i++)
        {
            sb.Append(DigitAt(digits, i));
        }

        if (decimals > 0)
        {
            sb.Append('.');
            for (var i = 0; i < decimals; i++)
            {
                sb.Append(DigitAt(digits, point + i));
            }
        }

        return sb.ToString();
    }

    private static string Sign(bool negative, Spec spec) => negative ? "-" : spec.Plus ? "+" : spec.Space ? " " : string.Empty;

    // The width counts runes, as Go does. The zero flag pads with zeros: after the sign for a number, in front for a string.
    private static string Pad(string text, Spec spec, bool zeroAfterSign)
    {
        var missing = spec.Width - Runes(text);
        if (missing <= 0)
        {
            return text;
        }

        if (spec.Minus)
        {
            return text + new string(' ', missing);
        }

        if (!spec.Zero)
        {
            return new string(' ', missing) + text;
        }

        var sign = zeroAfterSign && text.Length > 0 && text[0] is '-' or '+' or ' ' ? text[..1] : string.Empty;
        return sign + new string('0', missing) + text[sign.Length..];
    }

    private static int Runes(string text) => text.EnumerateRunes().Count();

    // A precision is a number of runes for a string.
    private static string Truncate(string text, int precision)
    {
        if (precision < 0)
        {
            return text;
        }

        var sb = new StringBuilder();
        foreach (var rune in text.EnumerateRunes().Take(precision))
        {
            sb.Append(rune.ToString());
        }

        return sb.ToString();
    }

    // %x of a string: its UTF-8 bytes in hex, the precision a number of bytes; # puts 0x in front and a space flag spaces
    // the bytes, each with its own 0x when # is set too.
    private static string Hex(string text, Spec spec)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        var count = spec.Precision >= 0 ? Math.Min(spec.Precision, bytes.Length) : bytes.Length;
        var prefix = spec.Verb == 'X' ? "0X" : "0x";
        var sb = new StringBuilder();
        for (var i = 0; i < count; i++)
        {
            if (spec.Space && i > 0)
            {
                sb.Append(' ');
            }

            if (spec.Sharp && (i == 0 || spec.Space))
            {
                sb.Append(prefix);
            }

            sb.Append(bytes[i].ToString(spec.Verb == 'X' ? "X2" : "x2", CultureInfo.InvariantCulture));
        }

        return sb.ToString();
    }

    // %q of a string: with # a raw string literal in backquotes when the text can be one, with + only ASCII.
    private static string Quoted(string text, Spec spec) =>
        spec.Sharp && CanBackquote(text) ? "`" + text + "`" : GoQuote(text, spec.Plus, '"');

    private static bool CanBackquote(string text)
    {
        foreach (var rune in text.EnumerateRunes())
        {
            if (rune.Value is '`' or 0x7F or 0xFEFF || (rune.Value < ' ' && rune.Value != '\t'))
            {
                return false;
            }
        }

        return true;
    }

    // A Go string literal, with \a, \b, \f, \n, \r, \t, \v, \\ and \" escaped, other control characters as
    // \x, and a rune that is not printable, a separator other than the space or a format character, as \u or \U.
    private static string GoQuote(string text, bool ascii, char quote)
    {
        var sb = new StringBuilder().Append(quote);
        foreach (var rune in text.EnumerateRunes())
        {
            var escape = rune.Value switch
            {
                '\a' => @"\a",
                '\b' => @"\b",
                '\f' => @"\f",
                '\n' => @"\n",
                '\r' => @"\r",
                '\t' => @"\t",
                '\v' => @"\v",
                '\\' => @"\\",
                '"' or '\'' when rune.Value == quote => "\\" + quote,
                < 0x20 or 0x7F => @"\x" + rune.Value.ToString("x2", CultureInfo.InvariantCulture),
                _ when (ascii && rune.Value > 0x7E) || !IsPrint(rune) => rune.Value > 0xFFFF
                        ? @"\U" + rune.Value.ToString("x8", CultureInfo.InvariantCulture)
                        : @"\u" + rune.Value.ToString("x4", CultureInfo.InvariantCulture),
                _ => null,
            };
            if (escape is null)
            {
                sb.Append(rune.ToString());
            }
            else
            {
                sb.Append(escape);
            }
        }

        return sb.Append(quote).ToString();
    }

    // Go's unicode.IsPrint: letters, marks, numbers, punctuation, symbols and the ASCII space.
    private static bool IsPrint(Rune rune) =>
        rune.Value == ' ' || Rune.GetUnicodeCategory(rune) is not (UnicodeCategory.Control or UnicodeCategory.Format
            or UnicodeCategory.SpaceSeparator or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator
            or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned or UnicodeCategory.Surrogate);

    /// <summary>The text of a value: a string as it is, a number, a boolean or null in their JSON form, and an array or an
    /// object in the form Rego prints it, <c>["a", 1]</c> and <c>{"k": true}</c> with the keys in order.</summary>
    private static string Value(JsonElement e)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.String:
                return e.GetString()!;
            case JsonValueKind.Number:
                return e.GetRawText();
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
