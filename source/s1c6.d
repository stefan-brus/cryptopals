/**
 * Set 1 Challenge 6
 * Breaking repeating-key XOR
 *
 * http://cryptopals.com/sets/1/challenges/6/
 */

module s1c6;

import crypto.decrypt;
import crypto.encrypt;

import util.array;
import util.encode;

import std.stdio;

/**
 * Constants
 */

enum FILE_PATH = "data/6.txt";
enum WHITESPACE = " \n\r\t";

/**
 * Main
 */

void main ( )
{
    auto file = File(FILE_PATH);
    string[] lines_buf;

    foreach ( string line; lines(file ) )
    {
        lines_buf ~= line;
    }

    auto stripped = lines_buf.flatten().removeAll(WHITESPACE);
    auto decoded = decodeBase64(stripped);
    auto key = decryptXor(decoded);

    writefln("The decrypted key: %s", key);

    auto decrypted = decoded.repeatingXor(key);

    writefln("The decrypted message:\n%s", decrypted);
}
