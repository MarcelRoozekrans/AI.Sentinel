using AI.Sentinel.ClaudeCode.Policy.Rego;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

/// <summary>The host runs <c>sprintf</c> as OPA does, which is Go's <c>fmt.Sprintf</c> on OPA's view of the arguments, and no
/// other builtin. Every expected value is what <c>opa eval</c> 1.22.4 prints for the same call.</summary>
public class RegoHostBuiltinsTests
{
    [Theory]
    [InlineData("\"hello %s\"", "[\"world\"]", "hello world")]
    [InlineData("\"%s and %s\"", "[\"a\", \"b\"]", "a and b")]
    [InlineData("\"%d files\"", "[3]", "3 files")]
    [InlineData("\"%5d|%-5d|%05d\"", "[42, 42, 42]", "   42|42   |00042")]
    [InlineData("\"%+d %+d\"", "[5, -5]", "+5 -5")]
    [InlineData("\"%.2f|%8.3f|%f\"", "[3.14159, 2.5, 1.0]", "3.14|   2.500|1.000000")]
    [InlineData("\"%v %v %v\"", "[true, null, 1.5]", "true null 1.5")]
    [InlineData("\"%q\"", "[\"a\\\"b\"]", "\"a\\\"b\"")]
    [InlineData("\"%x %X %o %b\"", "[255, 255, 8, 5]", "ff FF 10 101")]
    [InlineData("\"%x\"", "[\"hi\"]", "6869")]
    [InlineData("\"100%%\"", "[]", "100%")]
    [InlineData("\"%v\"", "[[\"a\", 1, {\"k\": true}]]", "[\"a\", 1, {\"k\": true}]")]
    [InlineData("\"%.3s\"", "[\"abcdef\"]", "abc")]
    [InlineData("\"%s\"", "[\"naïve ü\"]", "naïve ü")]
    [InlineData("\"%[1]s\"", "[\"rm\"]", "rm")]
    [InlineData("\"%[2]s %[1]s\"", "[\"a\", \"b\"]", "b a")]
    [InlineData("\"%[1]s %s\"", "[\"a\", \"b\"]", "a b")]
    [InlineData("\"%[1]d|%5[1]d|%[1]x\"", "[255]", "255|  255|ff")]
    [InlineData("\"%e|%E\"", "[1234.5678, 1234.5678]", "1.234568e+03|1.234568E+03")]
    [InlineData("\"%.2e|%.0e\"", "[-3.14159, 25000.0]", "-3.14e+00|2e+04")]
    [InlineData("\"%g|%G|%g\"", "[1e21, 1.5e-7, 123456789.5]", "1e+21|1.5E-07|1.234567895e+08")]
    [InlineData("\"%.3g|%.3G|%.0g|%.10g\"", "[1234.5678, 0.000012345, 2.5, 3.14]", "1.23e+03|1.23E-05|2|3.14")]
    [InlineData("\"%v|%v|%v\"", "[1e7, 0.00001, 100000.0]", "1e+07|1e-05|100000")]
    [InlineData("\"%.1f|%.0f|%.2f\"", "[2.25, 0.5, 9.995]", "2.2|0|9.99")]
    [InlineData("\"%05.1f|% .2e|%+g|%-7.2f|\"", "[-2.5, 3.0, 2.5, 2.5]", "-02.5| 3.00e+00|+2.5|2.50   |")]
    [InlineData("\"%#g|%#.3g|%#.0f|%#e\"", "[1.0, 2.0, 3.0, 4.0]", "1.00000|2.00|3.|4.000000e+00")]
    [InlineData("\"%b|%x|%X|%.2x|%#x\"", "[1.5, 1.5, -2.25, 3.14159, 0.5]", "6755399441055744p-52|0x1.8p+00|-0X1.2P+01|0x1.92p+01|0x1.0000p-01")]
    [InlineData("\"%v|%f|%x\"", "[-0.0, -0.0, 0.0]", "-0|-0.000000|0x0p+00")]
    [InlineData("\"%.3d|%08.3d|%#08x|%#o|%O|%#O|%#b\"", "[-7, 7, 255, 8, 8, 8, 5]", "-007|     007|0x000000ff|010|0o10|0o010|0b101")]
    [InlineData("\"%+.0d|%5.0d|\"", "[0, 0]", "|     |")]
    [InlineData("\"%c|%c|%q|%+q|%U|%#U|%.6U\"", "[65, -1, 39, 233, 65, 65, 7]", "A|\uFFFD|'\\''|'\\u00e9'|U+0041|U+0041 'A'|U+000007")]
    [InlineData("\"%d|%x|%+v\"", "[123456789012345678901234567890, 123456789012345678901234567890, 123456789012345678901234567890]", "123456789012345678901234567890|18ee90ff6c373e0ee4e3f0ad2|+123456789012345678901234567890")]
    [InlineData("\"%#v|%+v|%#v\"", "[\"a\\\"b\", 7, 1.5]", "\"a\\\"b\"|7|1.5")]
    [InlineData("\"%#q|%#q|%+q|%q\"", "[\"a b\", \"a`b\", \"naïve\", \"tab\\there\\u0001\"]", "`a b`|\"a`b\"|\"na\\u00efve\"|\"tab\\there\\x01\"")]
    [InlineData("\"%.2s|%5.1s|%-4s|%05s\"", "[\"naïve\", \"abc\", \"ab\", \"ab\"]", "na|    a|ab  |000ab")]
    [InlineData("\"%x|% x|%# X|%.2x\"", "[\"hi\", \"hi\", \"hi\", \"hello\"]", "6869|68 69|0X68 0X69|6865")]
    [InlineData("\"%v|%v|%v|%s\"", "[true, null, [1.0, \"x\", null], {\"b\": 1, \"a\": \"z\"}]", "true|null|[1.0, \"x\", null]|{\"a\": \"z\", \"b\": 1}")]
    [InlineData("\"%#d|%x|%o|%b\"", "[5, 0, 0, 0]", "5|0|0|0")]
    [InlineData("\"%x|%X|%.0x|%.1x|%b\"", "[5e-324, 1e-310, 1.5, 1.97, 1e300]", "0x1p-1074|0X1.2688B70E62BP-1030|0x1p+01|0x1.0p+01|6724873095247260p+944")]
    [InlineData("\"%f|%e|%E\"", "[1e16, 0.0, 0.0]", "10000000000000000.000000|0.000000e+00|0.000000E+00")]
    [InlineData("\"%#q|%#q|%#q\"", "[\"a\\u0001\", \"a\\u007f\", \"\\ufeffa\"]", "\"a\\x01\"|\"a\\x7f\"|\"\\ufeffa\"")]
    [InlineData("\"%q\"", "[\"\\u0007\\b\\f\\n\\r\\u000b\\\\\"]", "\"\\a\\b\\f\\n\\r\\v\\\\\"")]
    [InlineData("\"%q|%+q\"", "[\"\\udb40\\udc01\", \"\\ud83d\\ude00\"]", "\"\\U000e0001\"|\"\\U0001f600\"")]
    [InlineData("\"%U|%d|%v\"", "[-1, -123456789012345678901234567890, -123456789012345678901234567890]", "U+FFFFFFFFFFFFFFFF|-123456789012345678901234567890|-123456789012345678901234567890")]
    [InlineData("\"%[3]d %d\"", "[1, 2, 3]", "3 %!d(MISSING)")]
    [InlineData("\"%.[2]d\"", "[1, 2]", "2")]
    public void Sprintf_formats_like_opa(string format, string args, string expected)
    {
        var json = HostBuiltins.Sprintf(format, args);

        Assert.NotNull(json);
        Assert.Equal(expected, System.Text.Json.JsonDocument.Parse(json).RootElement.GetString());
    }

    [Theory]
    [InlineData("\"%d\"", "[]", "%!d(MISSING)")]
    [InlineData("\"x\"", "[1]", "x%!(EXTRA int64=1)")]
    [InlineData("\"%d\"", "[\"s\"]", "%!d(string=s)")]
    [InlineData("\"%d\"", "[1.5]", "%!d(float64=1.5)")]
    [InlineData("\"%z\"", "[1]", "%!z(int64=1)")]
    [InlineData("\"50%\"", "[]", "50%!(NOVERB)")]
    [InlineData("\"%[3]s\"", "[\"a\"]", "%!s(BADINDEX)")]
    [InlineData("\"%[0]s\"", "[\"a\"]", "%!s(BADINDEX)")]
    [InlineData("\"%[x]s\"", "[\"a\"]", "%!s(BADINDEX)")]
    [InlineData("\"%t\"", "[false]", "%!t(string=false)")]
    [InlineData("\"%f|%.2f|%+e\"", "[1, 3, 12345]", "%!f(int64=1)|%!f(int64=03)|%!e(int64=+12345)")]
    [InlineData("\"%s|%5d\"", "[1.5, 1.5]", "%!s(float64=1.5)|%!d(float64=  1.5)")]
    [InlineData("\"%5s|%-5d|\"", "[1, \"s\"]", "%!s(int64=    1)|%!d(string=s    )|")]
    [InlineData("\"%d|%f\"", "[123456789012345678901234567890, 123456789012345678901234567890]", "123456789012345678901234567890|%!f(big.Int=123456789012345678901234567890)")]
    [InlineData("\"x\"", "[1, 1.5, \"a\", true, null]", "x%!(EXTRA int64=1, float64=1.5, string=a, string=true, string=null)")]
    [InlineData("\"x\"", "[123456789012345678901234567890]", "x%!(EXTRA *big.Int=123456789012345678901234567890)")]
    [InlineData("\"%[1\"", "[\"a\"]", "%!(NOVERB)")]
    [InlineData("\"%[2]5d|%[1].2d\"", "[1, 2]", "%!d(BADINDEX)|%!d(BADINDEX)")]
    [InlineData("\"%[]d|%[0]d\"", "[1]", "%!d(BADINDEX)|%!d(BADINDEX)")]
    [InlineData("\"%5.\"", "[1]", "%!.(int64=    1)")]
    public void Sprintf_marks_a_mismatch_the_way_go_does(string format, string args, string expected)
    {
        var json = HostBuiltins.Sprintf(format, args);

        Assert.Equal(expected, System.Text.Json.JsonDocument.Parse(json!).RootElement.GetString());
    }

    [Theory]
    [InlineData("1", "[]")]
    [InlineData("\"%s\"", "\"not an array\"")]
    public void Sprintf_of_arguments_with_the_wrong_type_is_undefined(string format, string args) =>
        Assert.Null(HostBuiltins.Sprintf(format, args));

    [Fact]
    public void Only_sprintf_is_implemented()
    {
        Assert.True(HostBuiltins.IsImplemented("sprintf"));
        Assert.False(HostBuiltins.IsImplemented("uuid.rfc4122"));
        Assert.False(HostBuiltins.IsImplemented("http.send"));
    }
}
