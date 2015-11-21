/**
 * Set 1 Challenge 2
 * Fixed XOR
 *
 * Write a function that takes two equal-length buffers and produces their XOR combination.
 *
 * If your function works properly, then when you feed it the string:
 * 1c0111001f010100061a024b53535009181c
 *
 * after hex decoding, and when XOR'd against:
 * 686974207468652062756c6c277320657965
 *
 * should produce:
 * 746865206b696420646f6e277420706c6179
 */

module s1c2;

import crypto.encrypt;

import util.encode;

import std.stdio;

/**
 * Constants
 */

enum HEX_INPUT = "1c0111001f010100061a024b53535009181c";
enum HEX_KEY = "686974207468652062756c6c277320657965";

/**
 * Main
 */

void main ( )
{
    auto input = decodeHex(HEX_INPUT);
    auto key = decodeHex(HEX_KEY);

    writefln("Decoded input: %s", input);
    writefln("Decoded key: %s", key);

    auto result = fixedXor(input, key);

    writefln("Fixed XOR result: %s", result);
    writefln("Hex encoded: %s", encodeHex(result));
}
