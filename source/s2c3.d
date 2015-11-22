/**
 * Set 2 Challenge 11
 * An ECB/CBC detection oracle
 *
 * http://cryptopals.com/sets/2/challenges/11/
 */

module s2c3;

import crypto.aes;
import crypto.decrypt;
import crypto.util;

import util.encode;
import util.strings;

import std.random;
import std.stdio;

/**
 * Constants
 */

enum TEXT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/**
 * The "encryption oracle" described in the challenge
 *
 * Prepends and appends 5-10 random bytes to the input
 * Encrypts it with a random key
 * Uses ECB half the time, and CBC the other half
 *
 * Params:
 *      input = The text to encrypt
 *
 * Returns:
 *      The encrypted text
 */

string encryptionOracle ( string input )
{
    void appendRandomBytes ( ref string str )
    {
        enum MIN_BYTES = 5;
        enum MAX_BYTES = 10;
        auto len = uniform(MIN_BYTES, MAX_BYTES + 1);

        for ( auto _ = 0; _ < len; _++ )
        {
            str ~= cast(char)uniform(0, char.max + 1);
        }
    }

    string result;
    auto aes128 = AES!128();

    appendRandomBytes(result);
    result ~= input;
    appendRandomBytes(result);

    enum ECB = 1;
    enum CBC = 2;

    auto method = uniform(1, 3);
    auto key = generateKey(16);

    switch ( method )
    {
        case ECB:
            return aes128.encryptECB(result, key.fromBytes());

        case CBC:
            auto iv = generateKey(16);
            return aes128.encryptCBC(result, key.fromBytes(), iv);

        default:
            assert(false, "Unknown encryption method");
    }
}

/**
 * Main
 */

void main ( )
{
    auto encrypted = encryptionOracle(TEXT);

    writefln("Encrypted: %s", encrypted.encodeHex());

    if ( detectECB(encrypted) >= 1 )
    {
        writeln("ECB used");
    }
    else
    {
        writeln("CBC used");
    }
}
