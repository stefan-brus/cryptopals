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

    return str.padBytes(len, pad);
}

unittest
{
    import util.strings;

    assert("YELLOW SUBMARINE".toBytes().pkcs7Pad(20) == "YELLOW SUBMARINE".toBytes() ~ cast(ubyte[])[4, 4, 4, 4]);
}

/**
 * Pad the given bytes to the given length with the given byte
 *
 * Params:
 *      bytes = The bytes
 *      len = The length
 *      pad = The byte to pad with
 *
 * Returns:
 *      The padded byte array
 */

ubyte[] padBytes ( ubyte[] bytes, size_t len, ubyte pad )
in
{
    assert(len >= bytes.length);
}
body
{
    while ( bytes.length < len )
    {
        bytes ~= pad;
    }

    return bytes;
}
