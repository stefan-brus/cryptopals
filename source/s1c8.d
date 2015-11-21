/**
 * Set 1 Challenge 8
 * Detect AES in ECB mode
 *
 * http://cryptopals.com/sets/1/challenges/8/
 */

module s1c8;

import crypto.decrypt;

import util.array;
import util.encode;

import std.stdio;

/**
 * Constants
 */

enum FILE_PATH = "data/8.txt";
enum WHITESPACE = " \n\r\t";

/**
 * Main
 */

void main ( )
{
    auto file = File(FILE_PATH);
    uint score;
    size_t idx;
    string found_line;

    foreach ( size_t i, string line; lines(file ) )
    {
        auto cur_score = detectECB(line.removeAll(WHITESPACE).decodeHex());

        if ( detectECB(line) > score )
        {
            score = cur_score;
            idx = i;
            found_line = line.removeAll(WHITESPACE);
        }
    }

    writefln("Line %d was probably encrypted with ECB", idx + 1);
    writefln("Number of matching blocks: %d", score);
    writefln("The line: %s", found_line);
    writefln("Decoded: %s", found_line.decodeHex());
}
