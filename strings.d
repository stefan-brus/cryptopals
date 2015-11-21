/**
 * String utilities
 */

module strings;

import array;

/**
 * Convenience alias for mapping a function to a string
 */

alias stringMap ( alias Mapper ) = arrayMap!(Mapper, immutable(char), immutable(char));

unittest
{
    import std.ascii;

    assert("".stringMap!toLower == "");
    assert("ABCDEF".stringMap!toLower == "abcdef");
}

/**
 * Convert a string to a ubyte array
 *
 * Params:
 *      str = The string
 *
 * Returns:
 *      The string as an array of ubyte
 */

ubyte[] toBytes ( string str )
{
    ubyte[] result;

    foreach ( c; str )
    {
        result ~= c;
    }

    return result;
}

/**
 * Convert a ubyte array to a string
 *
 * Params:
 *      bytes = The ubyte array
 *
 * Returns:
 *      The string
 */

string fromBytes ( ubyte[] bytes )
{
    string result;

    foreach ( b; bytes )
    {
        result ~= b;
    }

    return result;
}
