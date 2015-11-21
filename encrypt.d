/**
 * Encryption utilities
 */

module encrypt;

import array;

/**
 * XOR two strings
 *
 * Params:
 *      s1 = The first string
 *      s2 = The second string
 *
 * Returns:
 *      zip xor s1 s2
 */

string fixedXor ( string s1, string s2 )
in
{
    assert(s1.length == s2.length);
}
body
{
    string result;

    foreach ( i, c; s1 )
    {
        result ~= c ^ s2[i];
    }

    return result;
}

/**
 * Encrypt the given string with the given key using repeating XOR
 *
 * Params:
 *      str = The string
 *      key = The key
 *
 * Returns:
 *      The encrypted string
 */

string repeatingXor ( string str, string key )
in
{
    assert(key.length <= str.length);
}
body
{
    auto repeated_key = replicate(str.length / key.length, key).flatten();

    auto remainder = str.length % key.length;

    if ( remainder > 0 )
    {
        repeated_key ~= key[0 .. remainder];
    }

    assert(repeated_key.length == str.length);

    return fixedXor(str, repeated_key);
}
