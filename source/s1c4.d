/**
 * Set 1 Challenge 4
 * Detect single-character XOR
 *
 * One of the 60-character strings in this file has been encrypted by single-character XOR.
 * Find it.
 *
 * (Your code from #3 should help.)
 */

module s1c4;

import crypto.decrypt;
import crypto.encrypt;

import util.array;
import util.encode;

import std.stdio;
import std.string;

/**
 * Constants
 */

enum FILE_PATH = "data/4.txt";

/**
 * Main
 */

void main ( )
{
    auto file = File(FILE_PATH);
    size_t idx;
    char chr;
    double score = 0;
    string msg;

    foreach ( size_t i, string line; lines(file) )
    {
        double cur_score = 0;
        char cur_chr;

        auto stripped = strip(line);
        auto decoded = decodeHex(stripped);
        decoded.getScores(cur_score, cur_chr);

        if ( cur_score > score )
        {
            idx = i;
            chr = cur_chr;
            score = cur_score;
            msg = stripped;
        }
    }

    writefln("Line %d was encrypted with %s, score: %f", idx + 1, chr, score);
    writefln("Message: %s", msg);
    writefln("Decrypted: %s", fixedXor(decodeHex(msg), replicate(msg.length / 2, chr)));
}
