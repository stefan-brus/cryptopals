/**
 * Encoding utilities
 */

module encode;

import array;

import std.exception;
import std.string;

/**
 * Constants
 */

enum BASE64_CODES = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Decode a hex-encoded string
 *
 * Params:
 *      str = The hex string
 *
 * Returns:
 *      The decoded string
 *
 * Throws:
 *      If a non-hex character is encountered
 */

string decodeHex ( string str )
out ( res )
{
    assert(res.length == str.length / 2);
}
body
{
    enforce(str.length % 2 == 0, "decodeHex: Invalid input length");

    int parseHex ( string cs )
    in
    {
        assert(cs.length == 2);
    }
    body
    {
        int toNum ( char c )
        out ( n )
        {
            assert(n >= 0x0 && n <= 0xf);
        }
        body
        {
            if ( c >= '0' && c <= '9' )
            {
                return c - '0';
            }
            else if ( c >= 'a' && c <= 'f' )
            {
                return c - 'a' + 0xa;
            }
            else if ( c >= 'A' && c <= 'F' )
            {
                return c - 'A' + 0xa;
            }
            else
            {
                throw new Exception("decodeHex: Invalid hex character: " ~ c);
            }
        }

        return toNum(cs[0]) * 0x10 + toNum(cs[1]);
    }

    string result;

    for ( auto i = 0; i < str.length; i += 2 )
    {
        result ~= cast(char)parseHex(str[i .. i + 2]);
    }

    return result;
}

/**
 * Encode a string to hex
 *
 * Params:
 *      str = The string
 *
 * Returns:
 *      The encoded string
 */

string encodeHex ( string str )
out ( res )
{
    assert(res.length == str.length * 2);
}
body
{
    int toHex ( char c )
    in
    {
        assert(c < 0x10 );
    }
    body
    {
        if ( c < 0xa )
        {
            return c + '0';
        }
        else
        {
            return c + 'a' - 0xa;
        }
    }

    string result;

    foreach ( c; str )
    {
        result ~= toHex((c & 0xf0) >> 4);
        result ~= toHex(c & 0x0f);
    }

    return result;
}

/**
 * Decode a Base64-encoded string
 *
 * Params:
 *      str = The Base64 string
 *
 * Returns:
 *      The decoded string
 *
 * Throws:
 *      If a non-Base64 character is encountered
 */

string decodeBase64 ( string str )
{
    enforce(str.length % 4 == 0, "decodeBase64: Invalid input length");

    string result;
    char[4] bytes;

    for ( auto i = 0; i < str.length; i += 4 )
    {
        for ( auto j = 0; j < bytes.length; j++ )
        {
            auto c = str[i + j];
            enforce(BASE64_CODES.contains(c) || c == '=', "decodeBase64: Invalid Base64 character: " ~ c);
            bytes[j] = c == '=' ? 0 : cast(char)BASE64_CODES.indexOf(c);
        }

        result ~= cast(char)(bytes[0] << 2) | (bytes[1] >> 4);
        if ( str[i + 2] != '=' ) result ~= cast(char)(bytes[1] << 4) | (bytes[2] >> 2);
        if ( str[i + 3] != '=' ) result ~= cast(char)(bytes[2] << 6) | bytes[3];
    }

    return result;
}

unittest
{
    assert(decodeBase64("") == "");
    assert(decodeBase64("UGVyIEFzcGVyYSBBZCBJbmZlcmk=") == "Per Aspera Ad Inferi");
}

/**
 * Encode a string to Base64
 *
 * Params:
 *      str = The string
 *
 * Returns:
 *      The encoded string
 */

string encodeBase64 ( string str )
{
    string result;

    for ( auto i = 0; i < str.length; i += 3 )
    {
        auto idx = (str[i] & 0xfc) >> 2;
        result ~= BASE64_CODES[idx];

        idx = (str[i] & 0x03) << 4;
        if ( i < str.length - 1 )
        {
            idx += (str[i + 1] & 0xf0) >> 4;
            result ~= BASE64_CODES[idx];

            idx = (str[i + 1] & 0x0f) << 2;
            if ( i < str.length - 2 )
            {
                idx += (str[i + 2] & 0xc0) >> 6;
                result ~= BASE64_CODES[idx];

                idx = str[i + 2] & 0x3f;
                result ~= BASE64_CODES[idx];
            }
            else
            {
                result ~= BASE64_CODES[idx];
                result ~= '=';
            }
        }
        else
        {
            result ~= BASE64_CODES[idx];
            result ~= "==";
        }
    }

    return result;
}
