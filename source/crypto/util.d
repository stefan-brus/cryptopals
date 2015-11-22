/**
 * Crypto utilities
 */

module crypto.util;

import std.random;

/**
 * Generate a random crypto key
 *
 * Params:
 *      len = The length of the key
 *
 * Returns:
 *      The generated key
 */

ubyte[] generateKey ( size_t len )
{
    ubyte[] result;

    while ( result.length < len )
    {
        result ~= cast(ubyte)uniform(0, ubyte.max + 1);
    }

    return result;
}
