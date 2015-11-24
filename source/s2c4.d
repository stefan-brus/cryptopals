/**
 * Set 2 Challenge 12
 * Byte-at-a-time ECB decryption (Simple)
 *
 * http://cryptopals.com/sets/2/challenges/12/
 */

module s2c4;

import crypto.aes;
import crypto.decrypt;
import crypto.util;

import util.array;
import util.encode;
import util.strings;

import std.stdio;

/**
 * Constants
 */

enum SECRET = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

/**
 * The "encryption oracle" described in the challenge
 *
 * Appends the secret string and encrypts the input with ECB with the given key
 *
 * Params:
 *      input = The text to encrypt
 *      key = The key to use
 *
 * Returns:
 *      The encrypted text
 */

string encryptionOracle ( string input, string key )
{
    static secret = SECRET.decodeBase64();
    static aes128 = AES!128();

    return aes128.encryptECB(input ~ secret, key);
}

/**
 * Main
 */

void main ( )
{
    auto key = generateKey(16).fromBytes();
    auto encrypted = encryptionOracle("", key);
    writefln("The encrypted bytes: %s", encrypted.encodeHex());

    // Detect the cipher block length
    // Feed identical bytes to the oracle until a repeating pattern occurs
    size_t block_size = 1;
    bool size_found;
    string test_encrypted;

    while ( !size_found )
    {
        auto text = cast(string)replicate(block_size * 2, 'A');
        auto test = encryptionOracle(text, key);

        if ( test[0 .. block_size].arrayEquals(test[block_size .. block_size * 2]) )
        {
            size_found = true;
            test_encrypted = test;
        }
        else
        {
            block_size++;
        }
    }

    assert(block_size == 16);
    writefln("Block size found: %d", block_size);

    assert(detectECB(test_encrypted) > 0);
    writefln("Oracle used ECB");
    writefln("Decrypting...");

    // Break the crypto as described in the challenge
    string known;

    while ( known.length < encrypted.length )
    {
        auto init_str = cast(string)replicate(block_size - (known.length % block_size) - 1, 'A');
        char[string] dictionary;

        for ( char i = 0; i < char.max; i++ )
        {
            dictionary[encryptionOracle(init_str ~ known ~ i, key)[0 .. init_str.length + known.length + 1]] = i;
        }

        auto crypto = encryptionOracle(init_str, key)[0 .. init_str.length + known.length + 1];

        if ( crypto in dictionary )
        {
            auto c = dictionary[crypto];

            write(c);
            stdout.flush();

            known ~= c;
        }
        else
        {
            assert(false);
        }
    }

    writeln();
}
