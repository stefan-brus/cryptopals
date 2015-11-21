/**
 * Decryption utilities
 */

module decrypt;

import array;
import encrypt;
import strings;

import std.algorithm;
import std.ascii;
import std.math;

/**
 * The statistical frequency of english language characters
 *
 * Source: http://www.data-compression.com/english.html
 */

enum CHAR_FREQ = [
    'a': 0.0651738,
    'b': 0.0124248,
    'c': 0.0217339,
    'd': 0.0349835,
    'e': 0.1041442,
    'f': 0.0197881,
    'g': 0.0158610,
    'h': 0.0492888,
    'i': 0.0558094,
    'j': 0.0009033,
    'k': 0.0050529,
    'l': 0.0331490,
    'm': 0.0202124,
    'n': 0.0564513,
    'o': 0.0596302,
    'p': 0.0137645,
    'q': 0.0008606,
    'r': 0.0497563,
    's': 0.0515760,
    't': 0.0729357,
    'u': 0.0225134,
    'v': 0.0082903,
    'w': 0.0171272,
    'x': 0.0013692,
    'y': 0.0145984,
    'z': 0.0007836,
    ' ': 0.1918182
];

/**
 * The block size of ECB based encryption
 */

enum ECB_BLOCK_SIZE = 16;

/**
 * Detect ECB encryption
 *
 * The problem with ECB is that it is stateless and deterministic;
 * the same 16 byte plaintext block will always produce
 * the same 16 byte ciphertext.
 *
 * Params:
 *      str = The string
 *
 * Returns:
 *      The number of blocks that were the same
 */

uint detectECB ( string str )
in
{
    assert(str.length >= ECB_BLOCK_SIZE);
}
body
{
    if ( str.length == ECB_BLOCK_SIZE ) return 0;

    auto split = str.paddedSplitN(ECB_BLOCK_SIZE, '\0');
    uint matches;

    foreach ( i, block1; split )
    {
        foreach ( block2; split[i + 1 .. $] )
        {
            if ( block1.arrayEquals(block2) )
            {
                matches++;
            }
        }
    }

    return matches;
}

/**
 * Decrypt a repeating-key XOR by guessing the key using the word scorer
 *
 * Params:
 *      str = The string to decrypt
 *
 * Returns:
 *      The guessed key
 */

string decryptXor ( string str )
{
    enum KEYSIZE_MIN = 2,
         KEYSIZE_MAX = 40;

    auto max_iter = str.length > KEYSIZE_MAX ? KEYSIZE_MAX : str.length;
    size_t guessed_size;
    double best_score = 10000.0;

    for ( auto key_size = KEYSIZE_MIN; key_size <= max_iter; key_size++ )
    {
        auto distances = str.paddedSplitN(key_size, '\0').combine!(hammingDistance, uint)();
        auto avg_dist = distances.average();
        auto normalized = avg_dist / key_size;

        if ( normalized < best_score )
        {
            best_score = normalized;
            guessed_size = key_size;
        }
    }

    auto transposed = str.paddedSplitN(guessed_size, '\0').transpose();
    assert(transposed.length == guessed_size);

    string key;

    foreach ( t; transposed )
    {
        double score = 0.0;
        char guess;

        for ( char c = 0; c < char.max; c++ )
        {
            auto cur_score = englishProbability(repeatingXor(t, [c]));

            if ( cur_score > score )
            {
                score = cur_score;
                guess = c;
            }
        }

        key ~= guess;
    }

    return key;
}

/**
 * Compute the hamming distance, number of differing bits, between two strings
 *
 * Params:
 *      s1 = The first string
 *      s2 = The second string
 *
 * Returns:
 *      The hamming distance
 */

uint hammingDistance ( string s1, string s2 )
in
{
    assert(s1.length == s2.length);
}
body
{
    uint result;

    foreach ( i, c; s1 )
    {
        auto diff = c ^ s2[i];

        for ( auto j = 0; j < 8 ; j++ )
        {
            if ( (diff & (1 << j)) > 0 )
            {
                result++;
            }
        }
    }

    return result;
}

unittest
{
    assert(hammingDistance("", "") == 0);
    assert(hammingDistance("aaaa", "abaa") == 2);
    assert(hammingDistance("aaaabb", "abaaaa") == 6);
    assert(hammingDistance("this is a test", "wokka wokka!!!") == 37);
}

/**
 * Check the probability that this is an english text
 *
 * Expects ~15% of the string to be whitespace, 2% punctuation, and
 * the rest characters scored by their frequency
 *
 * Params:
 *      text = The text string
 *
 * Returns:
 *      A probability between 0 and 1
 */

double englishProbability ( string text )
{
    enum SPACE_PERCENT = 0.15;
    enum PUNCTUATION_PERCENT = 0.02;
    enum LETTERS_PERCENT = 1.0 - SPACE_PERCENT - PUNCTUATION_PERCENT;

    double calcError ( alias FilterFn ) ( string str, double expected )
    {
        return abs(cast(double)str.arrayFilter!(FilterFn).length / str.length - expected);
    }

    auto space_error = calcError!isWhite(text, SPACE_PERCENT);
    auto punctuation_error = calcError!isReallyPunctuation(text, PUNCTUATION_PERCENT);
    auto letters_error = calcError!isAlpha(text.stringMap!toLower, LETTERS_PERCENT);
    auto others_error = calcError!isEnglish(text.stringMap!toLower, 1.0);

    auto filtered = text.arrayFilter!isAlpha;
    double char_score = 0.0;

    foreach ( c; filtered )
    {
        char_score += CHAR_FREQ[toLower(c)];
    }

    auto total_score = min(1.0, (char_score / filtered.length) / CHAR_FREQ.values.average());
    auto total_error = space_error + punctuation_error + letters_error + others_error;

    return max(0.0, total_score - total_error);
}

bool isReallyPunctuation ( char c )
{
    enum PUNCTUATION = ".,!?";

    return PUNCTUATION.contains(c);
}

bool isEnglish ( char c )
{
    return isWhite(c) || isReallyPunctuation(c) || isAlpha(c);
}

/**
 * Check the score of whether a given string has been XOR'ed with
 * the given character.
 *
 * Template params:
 *      Scorer = The score checking delegate
 *
 * Params:
 *      str = The string
 *      c = The character
 */

double checkScore ( alias Scorer ) ( string str, char c )
{
    auto result_str = fixedXor(str, replicate(str.length, c));
    double result = 0;

    foreach ( chr; result_str )
    {
        result += Scorer(chr);
    }

    return result;
}

double alphaScorer ( char c )
{
    return isAlpha(c) ? 1 : 0;
}

double wordScorer ( char c )
{
    enum PUNCTUATION = " .,?!";

    if ( isAlpha(c) )
    {
        return 1;
    }
    else if ( PUNCTUATION.contains(c) )
    {
        return 2;
    }
    else
    {
        return -1;
    }
}

double englishScorer ( char c )
{
    auto chr = toLower(c);

    if ( chr in CHAR_FREQ )
    {
        return CHAR_FREQ[chr];
    }

    return 0;
    /*else if ( " \n\r\t".contains(chr) )
    {
        return 0.05;
    }
    else
    {
        return -0.1;
    }*/
}

alias alphaScore = checkScore!alphaScorer;
alias wordScore = checkScore!wordScorer;
alias englishScore = checkScore!englishScorer;

/**
 * Get the best character and its score for the given string
 *
 * Params:
 *      str = The string
 *      score = Output, the score
 *      chr = Output, the best scoring character
 */

void getScores ( string str, out double score, out char chr )
{
    score = -10000.0;

    for ( char c = 0; c < char.max; c++ )
    {
        double cur_score = 0;
        if ( (cur_score = englishScore(str, c)) > score )
        {
            chr = c;
            score = cur_score;
        }
    }
}
