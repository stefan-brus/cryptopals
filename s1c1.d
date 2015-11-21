/**
 * Set 1 Challenge 1
 * Convert hex to base64
 *
 * The string:
 * 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
 *
 * Should produce:
 * SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
 *
 * So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
 *
 * Cryptopals Rule
 * Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.
 */

module s1c1;

import encode;

import std.stdio;

/**
 * Constants
 */

enum HEX_INPUT = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

/**
 * Main
 */

void main ( )
{
    writefln("Decoding hex input string: %s", HEX_INPUT);

    auto decoded_hex = decodeHex(HEX_INPUT);

    writefln("Result: %s", decoded_hex);

    writefln("Encoding result to Base64");

    auto encoded_base64 = encodeBase64(decoded_hex);

    writefln("Result: %s", encoded_base64);
}
