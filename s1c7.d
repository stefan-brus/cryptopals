/**
 * Set 1 Challenge 7
 * AES in ECB mode
 *
 * http://cryptopals.com/sets/1/challenges/7/
 */

module s1c7;

import aes;
import array;
import encode;

import std.stdio;

/**
 * Constants
 */

enum FILE_PATH = "data/7.txt";
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
    auto aes128 = AES!128();

    writeln(aes128.decrypt(decoded, KEY));
}
