/**
 * Set 2 Challenge 13
 * ECB cut-and-paste
 *
 * http://cryptopals.com/sets/2/challenges/13/
 */

module s2c5;

import crypto.aes;
import crypto.util;

import util.array;
import util.encode;
import util.strings;

import std.array;
import std.stdio;

/**
 * Globals
 */

static aes128 = AES!128();
static string key;

static this ( )
{
    key = generateKey(16).fromBytes();
}

/**
 * The profile type
 */

alias Profile = string[string];

/**
 * Parse a profile from a key-value string
 *
 * Params:
 *      str = The string
 *
 * Returns:
 *      The profile
 */

Profile parseProfile ( string str )
{
    Profile result;
    auto entries = str.split("&");

    foreach ( entry; entries )
    {
        auto pair = entry.split("=");
        assert(pair.length == 2);
        result[pair[0]] = pair[1];
    }

    return result;
}

unittest
{
    auto profile = parseProfile("foo=bar&baz=qux&zap=zazzle");
    assert(profile["foo"] == "bar");
    assert(profile["baz"] == "qux");
    assert(profile["zap"] == "zazzle");
}

/**
 * Create a profile for the given email address
 *
 * Strips special characters from the given string
 * Encrypts the string with ECB and the global key
 *
 * Params:
 *      email = The email address
 *
 * Returns:
 *      An encrypted profile for the given email address
 */

string profileFor ( string email )
{
    auto stripped = email.removeAll("&= \t\r\n");
    auto encrypted = aes128.encryptECB("email=" ~ email ~ "&uid=10&role=user", key);

    return encrypted;
}

/**
 * Decrypt a profile
 *
 * Params:
 *      str = The encrypted profile string
 *
 * Returns:
 *      The profile
 */

Profile decryptProfile ( string str )
out ( p )
{
    assert("email" in p);
    assert("uid" in p);
    assert("role" in p);
}
body
{
    auto decrypted = aes128.decryptECB(str, key);
    writefln(decrypted);
    return parseProfile(decrypted);
}

/**
 * Main
 */

void main ( )
{
    // Generate the first part of the cipher
    // It should be an encrypted 32-bit string ending with role=
    // Followed by 16 bits we won't use
    auto first_part = profileFor("oo@bar666.com");
    first_part = first_part[0 .. 32];
    writefln("First part of the cipher: %s", first_part.encodeHex());
    writefln("Length: %d", first_part.length);

    // Generate the second part of the cipher
    // The word admin should appear in the second block, which we will use
    auto second_part = profileFor("AAAAAAAAAAadmin           ");
    second_part = second_part[16 .. 32];
    writefln("Second part of the cipher: %s", second_part.encodeHex());

    // Decrypt the copy and pasted cipher
    auto decrypted = decryptProfile(first_part ~ second_part);
    writefln("Email: %s", decrypted["email"]);
    writefln("Uid: %s", decrypted["uid"]);
    writefln("Role: %s", decrypted["role"]);
}
