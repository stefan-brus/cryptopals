/**
 * Set 2 Challenge 1
 * Implement PKCS#7 padding
 *
 * http://cryptopals.com/sets/2/challenges/9/
 */

module s2c1;

import crypto.padding;

import util.strings;

import std.stdio;

/**
 * Constants
 */

enum STR = "YELLOW SUBMARINE";
enum PAD_LEN = 20;

/**
 * Main
 */

void main ( )
{
    writefln("Padded: %s", STR.toBytes().pkcs7Pad(PAD_LEN).fromBytes());
}
