/**
 * Set 2 Challenge 10
 * Implement CBC mode
 *
 * http://cryptopals.com/sets/2/challenges/10/
 */

module s2c2;

import crypto.aes;

import util.array;
import util.encode;

import std.stdio;

/**
 * Constants
 */

enum FILE_PATH = "data/10.txt";
enum WHITESPACE = " \n\r\t";
enum KEY = "YELLOW SUBMARINE";

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
    auto iv = replicate!ubyte(16, 0);
    auto aes128 = AES!128();

    writeln(aes128.decryptCBC(decoded, KEY, iv));
}
