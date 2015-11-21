/**
 * Padding functions
 */

module crypto.padding;

/**
 * PKCS#7 padding
 *
 * Pad the given string to the given length
 * The padding byte is the expected length minus the string length
 *
 * Params:
 *      str = The string
 *      len = The length to pad to
 *
 * Returns:
 *      The padded string
 */

ubyte[] pkcs7Pad ( ubyte[] str, size_t len )
in
{
    assert(len >= str.length);
    assert(len - str.length <= ubyte.max);
}
body
{
    auto pad = cast(char)(len - str.length);

    while ( str.length < len )
    {
        str ~= pad;
    }

    return str;
}

unittest
{
    import util.strings;

    assert("YELLOW SUBMARINE".toBytes().pkcs7Pad(20) == "YELLOW SUBMARINE".toBytes() ~ cast(ubyte[])[4, 4, 4, 4]);
}
