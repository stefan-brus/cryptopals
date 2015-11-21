/**
 * Set 1 Challenge 3
 * Single-byte XOR cipher
 *
 * The hex encoded string:
 * 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
 *
 * has been XOR'd against a single character. Find the key, decrypt the message.
 *
 * You can do this by hand. But don't: write code to do it for you.
 *
 * How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
 *
 * Achievement Unlocked
 * You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.
 */

module s1c3;

import array;
import decrypt;
import encode;
import encrypt;

import std.stdio;

/**
 * Constants
 */

enum HEX_INPUT = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

/**
 * Main
 */

void main ( )
{
    auto decoded = decodeHex(HEX_INPUT);
    char chr;
    double score = 0;

    for ( char c = 0; c < char.max; c++ )
    {
        double cur_score = 0;
        if ( (cur_score = alphaScore(decoded, c)) > score )
        {
            chr = c;
            score = cur_score;
        }
    }

    writefln("The character is: %s", chr);
    writefln("With a score of: %f", score);
    writefln("The message is: %s", fixedXor(decoded, replicate(decoded.length, chr)));
}
