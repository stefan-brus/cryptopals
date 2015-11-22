/**
 * Highly experimental AES functions
 */

module crypto.aes;

import crypto.padding;
import crypto.rijndael;

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
     * ECB mode:
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

    string encryptECB ( string text, string key )
    {
        enforce(key.length == BitSize / 8, format("AES%d: Invalid key length", BitSize));

        string result;

        this.state = State.init;
        this.expanded = rijndaelExpandKey(key.toBytes());

        auto bytes = text.toBytes();

        for ( auto i = 0; i < bytes.length; i+= BLOCK_SIZE )
        {
            if ( i + BLOCK_SIZE <= bytes.length )
            {
                this.state = toState(bytes[i .. i + BLOCK_SIZE].paddedSplitN(4, 0));
            }
            else
            {
                this.state = toState(bytes[i .. $].pkcs7Pad(BLOCK_SIZE).paddedSplitN(4, 0));
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

        assert(aes128.encryptECB(test1, key128) == expected1);
        assert(aes128.encryptECB(test2, key128) == expected2);
        assert(aes128.encryptECB(test3, key128) == expected3);
        assert(aes128.encryptECB(test4, key128) == expected4);

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

        assert(aes192.encryptECB(test1, key192) == expected1);
        assert(aes192.encryptECB(test2, key192) == expected2);
        assert(aes192.encryptECB(test3, key192) == expected3);
        assert(aes192.encryptECB(test4, key192) == expected4);

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

        assert(aes256.encryptECB(test1, key256) == expected1);
        assert(aes256.encryptECB(test2, key256) == expected2);
        assert(aes256.encryptECB(test3, key256) == expected3);
        assert(aes256.encryptECB(test4, key256) == expected4);
    }

    /**
     * Decrypt the given text with the given key
     *
     * ECB mode:
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

    string decryptECB ( string text, string key )
    {
        enforce(key.length == BitSize / 8, format("AES%d: Invalid key length", BitSize));

        string result;

        this.state = State.init;
        this.expanded = rijndaelExpandKey(key.toBytes());

        auto bytes = text.toBytes();

        for ( auto i = 0; i < bytes.length; i+= BLOCK_SIZE )
        {
            if ( i + BLOCK_SIZE <= bytes.length )
            {
                this.state = toState(bytes[i .. i + BLOCK_SIZE].paddedSplitN(4, 0));
            }
            else
            {
                this.state = toState(bytes[i .. $].pkcs7Pad(BLOCK_SIZE).paddedSplitN(4, 0));
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

        assert(aes128.decryptECB(cipher1, key128) == test1);
        assert(aes128.decryptECB(cipher2, key128) == test2);
        assert(aes128.decryptECB(cipher3, key128) == test3);
        assert(aes128.decryptECB(cipher4, key128) == test4);

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

        assert(aes192.decryptECB(cipher1, key192) == test1);
        assert(aes192.decryptECB(cipher2, key192) == test2);
        assert(aes192.decryptECB(cipher3, key192) == test3);
        assert(aes192.decryptECB(cipher4, key192) == test4);

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

        assert(aes256.decryptECB(cipher1, key256) == test1);
        assert(aes256.decryptECB(cipher2, key256) == test2);
        assert(aes256.decryptECB(cipher3, key256) == test3);
        assert(aes256.decryptECB(cipher4, key256) == test4);
    }

    /**
     * Encrypt the given text with the given key
     *
     * CBC mode:
     * The previous block cipher is added to the plaintext block before the next
     * cipher is run. The initialization vector is added to the first block.
     *
     * Params:
     *      text = The text
     *      key = The key
     *      iv = The initialization vector
     *
     * Returns:
     *      The encrypted text
     */

    string encryptCBC ( string text, string key, ubyte[] iv )
    {
        enforce(key.length == BitSize / 8, format("AES%d: Invalid key length", BitSize));
        enforce(iv.length == BLOCK_SIZE, format("AES%d: Invalid initialization vector length", BitSize));

        string result;

        this.state = State.init;
        this.addToState(iv);
        this.expanded = rijndaelExpandKey(key.toBytes());

        auto bytes = text.toBytes();

        for ( auto i = 0; i < bytes.length; i+= BLOCK_SIZE )
        {
            if ( i + BLOCK_SIZE <= bytes.length )
            {
                this.addToState(bytes[i .. i + BLOCK_SIZE]);
            }
            else
            {
                this.addToState(bytes[i .. $].padBytes(BLOCK_SIZE, 0));
            }

            this.encryptBlock();
            result ~= fromState(this.state).flatten().fromBytes();
        }

        result.length = text.length;

        return result;
    }

    unittest
    {
        // Test vectors: http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-cbc

        auto aes128 = AES!128();
        auto key128 = "2b7e151628aed2a6abf7158809cf4f3c".decodeHex();

        auto test1 = "6bc1bee22e409f96e93d7e117393172a".decodeHex();
        auto iv1 = "000102030405060708090A0B0C0D0E0F".decodeHex().toBytes();
        auto expected1 = "7649abac8119b246cee98e9b12e9197d".decodeHex();
        auto test2 = "ae2d8a571e03ac9c9eb76fac45af8e51".decodeHex();
        auto iv2 = "7649ABAC8119B246CEE98E9B12E9197D".decodeHex().toBytes();
        auto expected2 = "5086cb9b507219ee95db113a917678b2".decodeHex();
        auto test3 = "30c81c46a35ce411e5fbc1191a0a52ef".decodeHex();
        auto iv3 = "5086CB9B507219EE95DB113A917678B2".decodeHex().toBytes();
        auto expected3 = "73bed6b8e3c1743b7116e69e22229516".decodeHex();
        auto test4 = "f69f2445df4f9b17ad2b417be66c3710".decodeHex();
        auto iv4 = "73BED6B8E3C1743B7116E69E22229516".decodeHex().toBytes();
        auto expected4 = "3ff1caa1681fac09120eca307586e1a7".decodeHex();

        assert(aes128.encryptCBC(test1, key128, iv1) == expected1);
        assert(aes128.encryptCBC(test2, key128, iv2) == expected2);
        assert(aes128.encryptCBC(test3, key128, iv3) == expected3);
        assert(aes128.encryptCBC(test4, key128, iv4) == expected4);

        auto aes192 = AES!192();
        auto key192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b".decodeHex();

        test1 = "6bc1bee22e409f96e93d7e117393172a".decodeHex();
        iv1 = "000102030405060708090A0B0C0D0E0F".decodeHex().toBytes();
        expected1 = "4f021db243bc633d7178183a9fa071e8".decodeHex();
        test2 = "ae2d8a571e03ac9c9eb76fac45af8e51".decodeHex();
        iv2 = "4F021DB243BC633D7178183A9FA071E8".decodeHex().toBytes();
        expected2 = "b4d9ada9ad7dedf4e5e738763f69145a".decodeHex();
        test3 = "30c81c46a35ce411e5fbc1191a0a52ef".decodeHex();
        iv3 = "B4D9ADA9AD7DEDF4E5E738763F69145A".decodeHex().toBytes();
        expected3 = "571b242012fb7ae07fa9baac3df102e0".decodeHex();
        test4 = "f69f2445df4f9b17ad2b417be66c3710".decodeHex();
        iv4 = "571B242012FB7AE07FA9BAAC3DF102E0".decodeHex().toBytes();
        expected4 = "08b0e27988598881d920a9e64f5615cd".decodeHex();

        assert(aes192.encryptCBC(test1, key192, iv1) == expected1);
        assert(aes192.encryptCBC(test2, key192, iv2) == expected2);
        assert(aes192.encryptCBC(test3, key192, iv3) == expected3);
        assert(aes192.encryptCBC(test4, key192, iv4) == expected4);

        auto aes256 = AES!256();
        auto key256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".decodeHex();

        test1 = "6bc1bee22e409f96e93d7e117393172a".decodeHex();
        iv1 = "000102030405060708090A0B0C0D0E0F".decodeHex().toBytes();
        expected1 = "f58c4c04d6e5f1ba779eabfb5f7bfbd6".decodeHex();
        test2 = "ae2d8a571e03ac9c9eb76fac45af8e51".decodeHex();
        iv2 = "F58C4C04D6E5F1BA779EABFB5F7BFBD6".decodeHex().toBytes();
        expected2 = "9cfc4e967edb808d679f777bc6702c7d".decodeHex();
        test3 = "30c81c46a35ce411e5fbc1191a0a52ef".decodeHex();
        iv3 = "9CFC4E967EDB808D679F777BC6702C7D".decodeHex().toBytes();
        expected3 = "39f23369a9d9bacfa530e26304231461".decodeHex();
        test4 = "f69f2445df4f9b17ad2b417be66c3710".decodeHex();
        iv4 = "39F23369A9D9BACFA530E26304231461".decodeHex().toBytes();
        expected4 = "b2eb05e2c39be9fcda6c19078c6a9d1b".decodeHex();

        assert(aes256.encryptCBC(test1, key256, iv1) == expected1);
        assert(aes256.encryptCBC(test2, key256, iv2) == expected2);
        assert(aes256.encryptCBC(test3, key256, iv3) == expected3);
        assert(aes256.encryptCBC(test4, key256, iv4) == expected4);
    }

    /**
     * Decrypt the given text with the given key
     *
     * CBC mode:
     * The previous block cipher is added to the plaintext block before the next
     * cipher is run. The initialization vector is added to the first block.
     *
     * Params:
     *      text = The text
     *      key = The key
     *      iv = The initialization vector
     *
     * Returns:
     *      The decrypted text
     */

    string decryptCBC ( string text, string key, ubyte[] iv )
    {
        enforce(key.length == BitSize / 8, format("AES%d: Invalid key length", BitSize));
        enforce(iv.length == BLOCK_SIZE, format("AES%d: Invalid initialization vector length", BitSize));

        string result;

        this.state = State.init;
        this.addToState(iv);
        this.expanded = rijndaelExpandKey(key.toBytes());

        auto bytes = text.toBytes();
        auto prev_cipher = iv;

        /*
            For each block:
            - Store block as CUR_CIPHER
            - Decrypt the block
            - Add PREV_CIPHER to state (add iv for first block)
            - PREV_CIPHER = CUR_CIPHER
        */

        for ( auto i = 0; i < bytes.length; i+= BLOCK_SIZE )
        {
            ubyte[] cur_cipher;

            if ( i + BLOCK_SIZE <= bytes.length )
            {
                cur_cipher = bytes[i .. i + BLOCK_SIZE];
            }
            else
            {
                cur_cipher = bytes[i .. $].pkcs7Pad(BLOCK_SIZE);
            }

            this.state = toState(cur_cipher.paddedSplitN(4, 0));
            this.decryptBlock();
            this.addToState(prev_cipher);

            prev_cipher = cur_cipher;
            result ~= fromState(this.state).flatten().fromBytes();
        }

        result.length = text.length;

        return result;
    }

    unittest
    {
        // Test vectors: http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-cbc

        auto aes128 = AES!128();
        auto key128 = "2b7e151628aed2a6abf7158809cf4f3c".decodeHex();

        auto test1 = "6bc1bee22e409f96e93d7e117393172a".decodeHex();
        auto iv1 = "000102030405060708090A0B0C0D0E0F".decodeHex().toBytes();
        auto cipher1 = "7649abac8119b246cee98e9b12e9197d".decodeHex();
        auto test2 = "ae2d8a571e03ac9c9eb76fac45af8e51".decodeHex();
        auto iv2 = "7649ABAC8119B246CEE98E9B12E9197D".decodeHex().toBytes();
        auto cipher2 = "5086cb9b507219ee95db113a917678b2".decodeHex();
        auto test3 = "30c81c46a35ce411e5fbc1191a0a52ef".decodeHex();
        auto iv3 = "5086CB9B507219EE95DB113A917678B2".decodeHex().toBytes();
        auto cipher3 = "73bed6b8e3c1743b7116e69e22229516".decodeHex();
        auto test4 = "f69f2445df4f9b17ad2b417be66c3710".decodeHex();
        auto iv4 = "73BED6B8E3C1743B7116E69E22229516".decodeHex().toBytes();
        auto cipher4 = "3ff1caa1681fac09120eca307586e1a7".decodeHex();

        assert(aes128.decryptCBC(cipher1, key128, iv1) == test1);
        assert(aes128.decryptCBC(cipher2, key128, iv2) == test2);
        assert(aes128.decryptCBC(cipher3, key128, iv3) == test3);
        assert(aes128.decryptCBC(cipher4, key128, iv4) == test4);

        auto aes192 = AES!192();
        auto key192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b".decodeHex();

        test1 = "6bc1bee22e409f96e93d7e117393172a".decodeHex();
        iv1 = "000102030405060708090A0B0C0D0E0F".decodeHex().toBytes();
        cipher1 = "4f021db243bc633d7178183a9fa071e8".decodeHex();
        test2 = "ae2d8a571e03ac9c9eb76fac45af8e51".decodeHex();
        iv2 = "4F021DB243BC633D7178183A9FA071E8".decodeHex().toBytes();
        cipher2 = "b4d9ada9ad7dedf4e5e738763f69145a".decodeHex();
        test3 = "30c81c46a35ce411e5fbc1191a0a52ef".decodeHex();
        iv3 = "B4D9ADA9AD7DEDF4E5E738763F69145A".decodeHex().toBytes();
        cipher3 = "571b242012fb7ae07fa9baac3df102e0".decodeHex();
        test4 = "f69f2445df4f9b17ad2b417be66c3710".decodeHex();
        iv4 = "571B242012FB7AE07FA9BAAC3DF102E0".decodeHex().toBytes();
        cipher4 = "08b0e27988598881d920a9e64f5615cd".decodeHex();

        assert(aes192.decryptCBC(cipher1, key192, iv1) == test1);
        assert(aes192.decryptCBC(cipher2, key192, iv2) == test2);
        assert(aes192.decryptCBC(cipher3, key192, iv3) == test3);
        assert(aes192.decryptCBC(cipher4, key192, iv4) == test4);

        auto aes256 = AES!256();
        auto key256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".decodeHex();

        test1 = "6bc1bee22e409f96e93d7e117393172a".decodeHex();
        iv1 = "000102030405060708090A0B0C0D0E0F".decodeHex().toBytes();
        cipher1 = "f58c4c04d6e5f1ba779eabfb5f7bfbd6".decodeHex();
        test2 = "ae2d8a571e03ac9c9eb76fac45af8e51".decodeHex();
        iv2 = "F58C4C04D6E5F1BA779EABFB5F7BFBD6".decodeHex().toBytes();
        cipher2 = "9cfc4e967edb808d679f777bc6702c7d".decodeHex();
        test3 = "30c81c46a35ce411e5fbc1191a0a52ef".decodeHex();
        iv3 = "9CFC4E967EDB808D679F777BC6702C7D".decodeHex().toBytes();
        cipher3 = "39f23369a9d9bacfa530e26304231461".decodeHex();
        test4 = "f69f2445df4f9b17ad2b417be66c3710".decodeHex();
        iv4 = "39F23369A9D9BACFA530E26304231461".decodeHex().toBytes();
        cipher4 = "b2eb05e2c39be9fcda6c19078c6a9d1b".decodeHex();

        assert(aes256.decryptCBC(cipher1, key256, iv1) == test1);
        assert(aes256.decryptCBC(cipher2, key256, iv2) == test2);
        assert(aes256.decryptCBC(cipher3, key256, iv3) == test3);
        assert(aes256.decryptCBC(cipher4, key256, iv4) == test4);
    }

    /**
     * Add the given bytes to the state with XOR
     *
     * Params:
     *      bytes = The bytes
     */

    private void addToState ( ubyte[] bytes )
    in
    {
        assert(bytes.length == State.sizeof);
    }
    body
    {
        for ( auto i = 0; i < 4; i++ )
        {
            for ( auto j = 0; j < 4; j++ )
            {
                this.state[j][i] ^= bytes[i * 4 + j];
            }
        }
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
