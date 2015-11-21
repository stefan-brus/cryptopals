/**
 * Highly experimental AES functions
 */

module crypto.aes;

import crypto.padding;

import util.array;
import util.encode;
import util.strings;

import std.exception;
import std.format;

/**
 * The number of rounds for a given bit size
 */

enum ROUNDS = [
    128: 10,
    192: 12,
    256: 14
];

/**
 * AES encrypter
 *
 * Template params:
 *      BitSize = The key size in bits (128, 192 or 256)
 */

struct AES ( uint BitSize )
{
    /**
     * The block size
     */

    enum BLOCK_SIZE = 16;

    /**
     * The 4x4 state array
     */

    alias State = ubyte[4][4];

    State state;

    static assert(state.sizeof == BLOCK_SIZE);

    /**
     * Convert an array to a state, columns first
     *
     * Params:
     *      arr = The array
     *
     * Returns:
     *      The state
     */

    static State toState ( ubyte[][] arr )
    in
    {
        assert(arr.length == 4);
        assert(arr[0].length == 4 && arr[1].length == 4 && arr[2].length == 4 && arr[3].length == 4);
    }
    body
    {
        State result;

        foreach ( i, row; arr.transpose() )
        {
            foreach ( j, col; row )
            {
                result[i][j] = col;
            }
        }

        return result;
    }

    static ubyte[][] fromState ( State state )
    {
        ubyte[][] result;

        for ( auto i = 0; i < 4; i++ )
        {
            ubyte[] tmp;

            for ( auto j = 0; j < 4; j++ )
            {
                tmp ~= state[j][i];
            }

            result ~= tmp;
        }

        return result;
    }

    /**
     * The expanded key
     */

    ubyte[] expanded;

    /**
     * Encrypt the given text with the given key
     *
     * Currently only supports ECB mode:
     * Break the text into BLOCK_SIZE blocks, copy the block into the state
     * Run AES on the state and add it to the result
     *
     * Params:
     *      text = The text
     *      key = The key
     *
     * Returns:
     *      The encrypted text
     */

    string encrypt ( string text, string key )
    {
        enforce(key.length == BitSize / 8, format("AES%d: Invalid key length", BitSize));

        string result;

        this.state = State.init;
        this.expanded = rijndaelExpandKey(key.toBytes());

        auto bytes = text.toBytes();

        for ( auto i = 0; i < bytes.length; i+= BLOCK_SIZE )
        {
            if ( i + BLOCK_SIZE < bytes.length )
            {
                this.state = toState(bytes[i .. i + BLOCK_SIZE].paddedSplitN(4, 0));
            }
            else
            {
                auto tmp = bytes[i .. $].pkcs7Pad(BLOCK_SIZE - bytes[i .. $].length).paddedSplitN(4, 0);

                while ( tmp.length < 4 )
                {
                    tmp ~= [0, 0, 0, 0];
                }

                this.state = toState(tmp);
            }

            this.encryptBlock();
            result ~= fromState(this.state).flatten().fromBytes();
        }

        result.length = text.length;

        return result;
    }

    unittest
    {
        // Test vectors: http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-ecb

        auto aes128 = AES!128();
        auto key128 = "2b7e151628aed2a6abf7158809cf4f3c".decodeHex();

        auto test1 = "6bc1bee22e409f96e93d7e117393172a".decodeHex();
        auto expected1 = "3ad77bb40d7a3660a89ecaf32466ef97".decodeHex();
        auto test2 = "ae2d8a571e03ac9c9eb76fac45af8e51".decodeHex();
        auto expected2 = "f5d3d58503b9699de785895a96fdbaaf".decodeHex();
        auto test3 = "30c81c46a35ce411e5fbc1191a0a52ef".decodeHex();
        auto expected3 = "43b1cd7f598ece23881b00e3ed030688".decodeHex();
        auto test4 = "f69f2445df4f9b17ad2b417be66c3710".decodeHex();
        auto expected4 = "7b0c785e27e8ad3f8223207104725dd4".decodeHex();

        assert(aes128.encrypt(test1, key128) == expected1);
        assert(aes128.encrypt(test2, key128) == expected2);
        assert(aes128.encrypt(test3, key128) == expected3);
        assert(aes128.encrypt(test4, key128) == expected4);

        auto aes192 = AES!192();
        auto key192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b".decodeHex();

        test1 = "6bc1bee22e409f96e93d7e117393172a".decodeHex();
        expected1 = "bd334f1d6e45f25ff712a214571fa5cc".decodeHex();
        test2 = "ae2d8a571e03ac9c9eb76fac45af8e51".decodeHex();
        expected2 = "974104846d0ad3ad7734ecb3ecee4eef".decodeHex();
        test3 = "30c81c46a35ce411e5fbc1191a0a52ef".decodeHex();
        expected3 = "ef7afd2270e2e60adce0ba2face6444e".decodeHex();
        test4 = "f69f2445df4f9b17ad2b417be66c3710".decodeHex();
        expected4 = "9a4b41ba738d6c72fb16691603c18e0e".decodeHex();

        assert(aes192.encrypt(test1, key192) == expected1);
        assert(aes192.encrypt(test2, key192) == expected2);
        assert(aes192.encrypt(test3, key192) == expected3);
        assert(aes192.encrypt(test4, key192) == expected4);

        auto aes256 = AES!256();
        auto key256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".decodeHex();

        test1 = "6bc1bee22e409f96e93d7e117393172a".decodeHex();
        expected1 = "f3eed1bdb5d2a03c064b5a7e3db181f8".decodeHex();
        test2 = "ae2d8a571e03ac9c9eb76fac45af8e51".decodeHex();
        expected2 = "591ccb10d410ed26dc5ba74a31362870".decodeHex();
        test3 = "30c81c46a35ce411e5fbc1191a0a52ef".decodeHex();
        expected3 = "b6ed21b99ca6f4f9f153e7b1beafed1d".decodeHex();
        test4 = "f69f2445df4f9b17ad2b417be66c3710".decodeHex();
        expected4 = "23304b7a39f9f3ff067d8d8f9e24ecc7".decodeHex();

        assert(aes256.encrypt(test1, key256) == expected1);
        assert(aes256.encrypt(test2, key256) == expected2);
        assert(aes256.encrypt(test3, key256) == expected3);
        assert(aes256.encrypt(test4, key256) == expected4);
    }

    /**
     * Decrypt the given text with the given key
     *
     * Currently only supports ECB mode:
     * Break the text into BLOCK_SIZE blocks, copy the block into the state
     * Run inverse AES on the state and add it to the result
     *
     * Params:
     *      text = The text
     *      key = The key
     *
     * Returns:
     *      The decrypted text
     */

    string decrypt ( string text, string key )
    {
        enforce(key.length == BitSize / 8, format("AES%d: Invalid key length", BitSize));

        string result;

        this.state = State.init;
        this.expanded = rijndaelExpandKey(key.toBytes());

        auto bytes = text.toBytes();

        for ( auto i = 0; i < bytes.length; i+= BLOCK_SIZE )
        {
            if ( i + BLOCK_SIZE < bytes.length )
            {
                this.state = toState(bytes[i .. i + BLOCK_SIZE].paddedSplitN(4, 0));
            }
            else
            {
                auto tmp = bytes[i .. $].pkcs7Pad(BLOCK_SIZE - bytes[i .. $].length).paddedSplitN(4, 0);

                while ( tmp.length < 4 )
                {
                    tmp ~= [0, 0, 0, 0];
                }

                this.state = toState(tmp);
            }

            this.decryptBlock();
            result ~= fromState(this.state).flatten().fromBytes();
        }

        result.length = text.length;

        return result;
    }

    unittest
    {
        // Test vectors: http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-ecb

        auto aes128 = AES!128();
        auto key128 = "2b7e151628aed2a6abf7158809cf4f3c".decodeHex();

        auto test1 = "6bc1bee22e409f96e93d7e117393172a".decodeHex();
        auto cipher1 = "3ad77bb40d7a3660a89ecaf32466ef97".decodeHex();
        auto test2 = "ae2d8a571e03ac9c9eb76fac45af8e51".decodeHex();
        auto cipher2 = "f5d3d58503b9699de785895a96fdbaaf".decodeHex();
        auto test3 = "30c81c46a35ce411e5fbc1191a0a52ef".decodeHex();
        auto cipher3 = "43b1cd7f598ece23881b00e3ed030688".decodeHex();
        auto test4 = "f69f2445df4f9b17ad2b417be66c3710".decodeHex();
        auto cipher4 = "7b0c785e27e8ad3f8223207104725dd4".decodeHex();

        assert(aes128.decrypt(cipher1, key128) == test1);
        assert(aes128.decrypt(cipher2, key128) == test2);
        assert(aes128.decrypt(cipher3, key128) == test3);
        assert(aes128.decrypt(cipher4, key128) == test4);

        auto aes192 = AES!192();
        auto key192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b".decodeHex();

        test1 = "6bc1bee22e409f96e93d7e117393172a".decodeHex();
        cipher1 = "bd334f1d6e45f25ff712a214571fa5cc".decodeHex();
        test2 = "ae2d8a571e03ac9c9eb76fac45af8e51".decodeHex();
        cipher2 = "974104846d0ad3ad7734ecb3ecee4eef".decodeHex();
        test3 = "30c81c46a35ce411e5fbc1191a0a52ef".decodeHex();
        cipher3 = "ef7afd2270e2e60adce0ba2face6444e".decodeHex();
        test4 = "f69f2445df4f9b17ad2b417be66c3710".decodeHex();
        cipher4 = "9a4b41ba738d6c72fb16691603c18e0e".decodeHex();

        assert(aes192.decrypt(cipher1, key192) == test1);
        assert(aes192.decrypt(cipher2, key192) == test2);
        assert(aes192.decrypt(cipher3, key192) == test3);
        assert(aes192.decrypt(cipher4, key192) == test4);

        auto aes256 = AES!256();
        auto key256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".decodeHex();

        test1 = "6bc1bee22e409f96e93d7e117393172a".decodeHex();
        cipher1 = "f3eed1bdb5d2a03c064b5a7e3db181f8".decodeHex();
        test2 = "ae2d8a571e03ac9c9eb76fac45af8e51".decodeHex();
        cipher2 = "591ccb10d410ed26dc5ba74a31362870".decodeHex();
        test3 = "30c81c46a35ce411e5fbc1191a0a52ef".decodeHex();
        cipher3 = "b6ed21b99ca6f4f9f153e7b1beafed1d".decodeHex();
        test4 = "f69f2445df4f9b17ad2b417be66c3710".decodeHex();
        cipher4 = "23304b7a39f9f3ff067d8d8f9e24ecc7".decodeHex();

        assert(aes256.decrypt(cipher1, key256) == test1);
        assert(aes256.decrypt(cipher2, key256) == test2);
        assert(aes256.decrypt(cipher3, key256) == test3);
        assert(aes256.decrypt(cipher4, key256) == test4);
    }

    /**
     * Encrypt the block currently in the state
     *
     * Returns:
     *      The encrypted text
     */

    private void encryptBlock ( )
    {
        // Initial round - add the round key
        this.addRoundKey(0);

        for ( auto i = 1; i <= ROUNDS[BitSize]; i++ )
        {
            this.subBytes();
            this.shiftRows();
            if ( i < ROUNDS[BitSize] ) this.mixColumns();
            this.addRoundKey(i);
        }
    }

    /**
     * Decrypt the block currently in the state
     *
     * Returns:
     *      The decrypted text
     */

    private void decryptBlock ( )
    {
        // Initial round - add the round key
        this.addRoundKey(ROUNDS[BitSize]);

        for ( auto i = ROUNDS[BitSize] - 1; i >= 0; i-- )
        {
            this.invShiftRows();
            this.invSubBytes();
            this.addRoundKey(i);
            if ( i > 0 ) this.invMixColumns();
        }
    }

    /**
     * Substitute the bytes in the state with their sbox values
     */

    private void subBytes ( )
    {
        foreach ( ref row; this.state )
        {
            foreach ( ref b; row )
            {
                b = RIJNDAEL_SBOX[b];
            }
        }
    }

    /**
     * Substitute the bytes in the state with their inverse sbox values
     */

    private void invSubBytes ( )
    {
        foreach ( ref row; this.state )
        {
            foreach ( ref b; row )
            {
                b = RIJNDAEL_INVSBOX[b];
            }
        }
    }

    /**
     * Galois field multiplication
     *
     * From https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael.27s_finite_field
     *
     * Params:
     *      a = The first byte
     *      b = The second byte
     *
     * Returns:
     *      The multiplication result
     */

    ubyte gmul ( ubyte a, ubyte b )
    {
        ubyte result;

        for ( auto i = 0; i < 8; i++ )
        {
            if ( (b & 1) != 0 )
            {
                result ^= a;
            }

            auto set = (a & 0x80) != 0;
            a <<= 1;

            if ( set )
            {
                a ^= 0x1b;
            }

            b >>= 1;
        }

        return result;
    }

    /**
     * Mix the columns of the state
     *
     * Based on https://en.wikipedia.org/wiki/Rijndael_mix_columns#Implementation_example
     */

    private void mixColumns ( )
    {
        State tmp_state;

        for ( auto i = 0; i < this.state.length; i++ )
        {
            tmp_state[0][i] = gmul(2, this.state[0][i]) ^ gmul(3, this.state[1][i]) ^ this.state[2][i] ^ this.state[3][i];
            tmp_state[1][i] = this.state[0][i] ^ gmul(2, this.state[1][i]) ^ gmul(3, this.state[2][i]) ^ this.state[3][i];
            tmp_state[2][i] = this.state[0][i] ^ this.state[1][i] ^ gmul(2, this.state[2][i]) ^ gmul(3, this.state[3][i]);
            tmp_state[3][i] = gmul(3, this.state[0][i]) ^ this.state[1][i] ^ this.state[2][i] ^ gmul(2, this.state[3][i]);
        }

        this.state = tmp_state;
    }

    unittest
    {
        enum TEST_STATE = [
            [219, 242, 1, 198],
            [19, 10, 1, 198],
            [83, 34, 1, 198],
            [69, 92, 1, 198]
        ];

        enum EXPECTED = [
            [142, 159, 1, 198],
            [77, 220, 1, 198],
            [161, 88, 1, 198],
            [188, 157, 1, 198]
        ];

        AES aes;
        aes.state = TEST_STATE;
        aes.mixColumns();

        assert(aes.state == EXPECTED);

        enum TEST_STATE2 = [
            [0xd4, 0xe0, 0xb8, 0x1e],
            [0xbf, 0xb4, 0x41, 0x27],
            [0x5d, 0x52, 0x11, 0x98],
            [0x30, 0xae, 0xf1, 0xe5]
        ];

        enum EXPECTED2 = [
            [0x04, 0xe0, 0x48, 0x28],
            [0x66, 0xcb, 0xf8, 0x06],
            [0x81, 0x19, 0xd3, 0x26],
            [0xe5, 0x9a, 0x7a, 0x4c]
        ];

        aes.state = TEST_STATE2;
        aes.mixColumns();

        assert(aes.state == EXPECTED2);
    }

    /**
     * Mix the columns of the state with the inverse mix column matrix
     *
     * https://en.wikipedia.org/wiki/Rijndael_mix_columns#InverseMixColumns
     */

    private void invMixColumns ( )
    {
        State tmp_state;

        for ( auto i = 0; i < this.state.length; i++ )
        {
            tmp_state[0][i] = gmul(14, this.state[0][i]) ^ gmul(11, this.state[1][i]) ^ gmul(13, this.state[2][i]) ^ gmul(9, this.state[3][i]);
            tmp_state[1][i] = gmul(9, this.state[0][i]) ^ gmul(14, this.state[1][i]) ^ gmul(11, this.state[2][i]) ^ gmul(13, this.state[3][i]);
            tmp_state[2][i] = gmul(13, this.state[0][i]) ^ gmul(9, this.state[1][i]) ^ gmul(14, this.state[2][i]) ^ gmul(11, this.state[3][i]);
            tmp_state[3][i] = gmul(11, this.state[0][i]) ^ gmul(13, this.state[1][i]) ^ gmul(9, this.state[2][i]) ^ gmul(14, this.state[3][i]);
        }

        this.state = tmp_state;
    }

    /**
     * Shift the rows of the state ROW_NUMBER bytes to the left
     *
     * The first row is untouched
     */

    private void shiftRows ( )
    {
        ubyte tmp;

        // Rotate the second row 1 column to the left
        tmp = this.state[1][0];
        this.state[1][0] = this.state[1][1];
        this.state[1][1] = this.state[1][2];
        this.state[1][2] = this.state[1][3];
        this.state[1][3] = tmp;

        // Rotate the third row 2 column to the left
        tmp = this.state[2][0];
        this.state[2][0] = this.state[2][2];
        this.state[2][2] = tmp;
        tmp = this.state[2][1];
        this.state[2][1] = this.state[2][3];
        this.state[2][3] = tmp;

        // Rotate the fourth row 3 column to the left
        tmp = this.state[3][0];
        this.state[3][0] = this.state[3][3];
        this.state[3][3] = this.state[3][2];
        this.state[3][2] = this.state[3][1];
        this.state[3][1] = tmp;
    }

    /**
     * Shift the rows of the state ROW_NUMBER bytes to the right
     *
     * The first row is untouched
     */

    private void invShiftRows ( )
    {
        ubyte tmp;

        // Rotate the second row 1 column to the right
        tmp = this.state[1][3];
        this.state[1][3] = this.state[1][2];
        this.state[1][2] = this.state[1][1];
        this.state[1][1] = this.state[1][0];
        this.state[1][0] = tmp;

        // Rotate the third row 2 column to the right
        tmp = this.state[2][0];
        this.state[2][0] = this.state[2][2];
        this.state[2][2] = tmp;
        tmp = this.state[2][1];
        this.state[2][1] = this.state[2][3];
        this.state[2][3] = tmp;

        // Rotate the fourth row 3 column to the right
        tmp = this.state[3][0];
        this.state[3][0] = this.state[3][1];
        this.state[3][1] = this.state[3][2];
        this.state[3][2] = this.state[3][3];
        this.state[3][3] = tmp;
    }

    /**
     * Add a round key to the state
     *
     * Params:
     *      round = The round number
     */

    private void addRoundKey ( uint round )
    in
    {
        assert(round <= ROUNDS[BitSize]);
    }
    body
    {
        for ( auto i = 0; i < 4; i++ )
        {
            for ( auto j = 0; j < 4; j++ )
            {
                this.state[j][i] ^= this.expanded[round * BLOCK_SIZE + i * 4 + j];
            }
        }
    }
}

/**
 * Utility alias for a 32-bit word
 */

alias RIJNDAEL_WORD = ubyte[4];

static assert(RIJNDAEL_WORD.sizeof == 4);

/**
 * From https://en.wikipedia.org/wiki/Rijndael_S-box
 */

enum ubyte[] RIJNDAEL_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
];

static assert(RIJNDAEL_SBOX.length == ubyte.max + 1);

/**
 * From https://en.wikipedia.org/wiki/Rijndael_S-box#Inverse_S-box
 */

enum ubyte[] RIJNDAEL_INVSBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

static assert(RIJNDAEL_INVSBOX.length == ubyte.max + 1);

/**
 * From https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 */

enum ubyte[] RIJNDAEL_RCON = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
];

static assert(RIJNDAEL_RCON.length == ubyte.max + 1);

/**
 * Supported key sizes and their expected expanded key sizes
 */

enum EXPANDED_SIZES = [
    16: 176,
    24: 208,
    32: 240
];

/**
 * Expand an AES key
 *
 * From https://en.wikipedia.org/wiki/Rijndael_key_schedule#The_key_schedule
 *
 * Params:
 *      key = The key
 *
 * Returns:
 *      The expanded key
 */

ubyte[] rijndaelExpandKey ( ubyte[] key )
in
{
    assert(key.length in EXPANDED_SIZES);
}
out ( res )
{
    assert(res.length == EXPANDED_SIZES[key.length]);
}
body
{
    // Set the first SIZE bytes of the expaned key to the cipher key
    ubyte[] result;
    result.length = EXPANDED_SIZES[key.length];
    result[0 .. key.length] = key;

    auto cur_len = key.length;
    auto rcon_iter = cast(ubyte)1;

    while ( cur_len < EXPANDED_SIZES[key.length] )
    {
        RIJNDAEL_WORD word = result[cur_len - RIJNDAEL_WORD.sizeof .. cur_len];

        // Every SIZE bytes, run the core on the word to be added
        // Increment the rcon counter
        if ( cur_len % key.length == 0 )
        {
            word = rijndaelKeyScheduleCore(word, rcon_iter);
            rcon_iter++;
        }

        // For 256-bit cipher keys, add an sbox to the calculation
        if ( key.length == 32 && cur_len % key.length == 16 )
        {
            foreach ( ref b; word )
            {
                b = RIJNDAEL_SBOX[b];
            }
        }

        // XOR the new word with the word SIZE blocks before this one
        foreach ( i, b; word )
        {
            result[cur_len + i] = result[cur_len + i - key.length] ^ b;
        }

        cur_len += word.length;
    }

    return result;
}

unittest
{
    /**
     * The tests performed here are the test vectors from:
     * http://www.samiam.org/key-schedule.html
     */

    auto input_128 = "000102030405060708090a0b0c0d0e0f".decodeHex().toBytes();
    auto res_128 =
    "000102030405060708090a0b0c0d0e0f"
    "d6aa74fdd2af72fadaa678f1d6ab76fe"
    "b692cf0b643dbdf1be9bc5006830b3fe"
    "b6ff744ed2c2c9bf6c590cbf0469bf41"
    "47f7f7bc95353e03f96c32bcfd058dfd"
    "3caaa3e8a99f9deb50f3af57adf622aa"
    "5e390f7df7a69296a7553dc10aa31f6b"
    "14f9701ae35fe28c440adf4d4ea9c026"
    "47438735a41c65b9e016baf4aebf7ad2"
    "549932d1f08557681093ed9cbe2c974e"
    "13111d7fe3944a17f307a78b4d2b30c5";

    assert(rijndaelExpandKey(input_128) == res_128.decodeHex().toBytes());

    auto input_192 = "000102030405060708090a0b0c0d0e0f1011121314151617".decodeHex().toBytes();
    auto res_192 =
    "000102030405060708090a0b0c0d0e0f"
    "10111213141516175846f2f95c43f4fe"
    "544afef55847f0fa4856e2e95c43f4fe"
    "40f949b31cbabd4d48f043b810b7b342"
    "58e151ab04a2a5557effb5416245080c"
    "2ab54bb43a02f8f662e3a95d66410c08"
    "f501857297448d7ebdf1c6ca87f33e3c"
    "e510976183519b6934157c9ea351f1e0"
    "1ea0372a995309167c439e77ff12051e"
    "dd7e0e887e2fff68608fc842f9dcc154"
    "859f5f237a8d5a3dc0c02952beefd63a"
    "de601e7827bcdf2ca223800fd8aeda32"
    "a4970a331a78dc09c418c271e3a41d5d";

    assert(rijndaelExpandKey(input_192) == res_192.decodeHex().toBytes());

    auto input_256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".decodeHex().toBytes();
    auto res_256 =
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
    "a573c29fa176c498a97fce93a572c09c"
    "1651a8cd0244beda1a5da4c10640bade"
    "ae87dff00ff11b68a68ed5fb03fc1567"
    "6de1f1486fa54f9275f8eb5373b8518d"
    "c656827fc9a799176f294cec6cd5598b"
    "3de23a75524775e727bf9eb45407cf39"
    "0bdc905fc27b0948ad5245a4c1871c2f"
    "45f5a66017b2d387300d4d33640a820a"
    "7ccff71cbeb4fe5413e6bbf0d261a7df"
    "f01afafee7a82979d7a5644ab3afe640"
    "2541fe719bf500258813bbd55a721c0a"
    "4e5a6699a9f24fe07e572baacdf8cdea"
    "24fc79ccbf0979e9371ac23c6d68de36";
}

/**
 * Rijndael key schedule core
 *
 * From https://en.wikipedia.org/wiki/Rijndael_key_schedule#Key_schedule_core
 *
 * Params:
 *      word = The word
 *      iter = The iteration number
 *
 * Returns:
 *      The scheduled key
 */

RIJNDAEL_WORD rijndaelKeyScheduleCore ( RIJNDAEL_WORD word, ubyte iter )
{
    RIJNDAEL_WORD result;

    auto rotated = rijndaelRotate(word);

    foreach ( i, b; rotated )
    {
        result[i] = RIJNDAEL_SBOX[b];
    }

    result[0] = result[0] ^ RIJNDAEL_RCON[iter];

    return result;
}

unittest
{
    assert(rijndaelKeyScheduleCore([0x1d, 0x2c, 0x3a, 0x4f], 1) == [0x70, 0x80, 0x84, 0xa4]);
}

/**
 * Rotate a word 8 bits to the left
 *
 * Params:
 *      word = The word
 *
 * Returns:
 *      The rotated word
 */

RIJNDAEL_WORD rijndaelRotate ( RIJNDAEL_WORD word )
{
    return [word[1], word[2], word[3], word[0]];
}

unittest
{
    assert(rijndaelRotate([0x1d, 0x2c, 0x3a, 0x4f]) == [0x2c, 0x3a, 0x4f, 0x1d]);
}
