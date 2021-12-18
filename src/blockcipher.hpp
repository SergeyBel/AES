#ifndef KRYPT_BLOCKCIPHER_HPP
#define KRYPT_BLOCKCIPHER_HPP

#include <iostream>
#include <cstring>
#include "types.hpp"

namespace Krypt
{
    class BLOCK_CIPHER
    {
        public:
            //  BLOCK_SIZE IN BYTES
            size_t BLOCK_SIZE;

            virtual void EncryptBlock() {};
            virtual void DecryptBlock() {};
    };

    /// @def AES BLOCK CIPHER, ENCRYPTION - DECRYPTION OF 16 BYTES BLOCK
    class AES : BLOCK_CIPHER
    {
        private:
            
            size_t Nk;
            size_t Nr;
            Bytes *RoundedKeys;
            bool isRoundKeySet = false;

            void SubBytes(unsigned char state[4][4]);
            void InvSubBytes(unsigned char state[4][4]);

            void ShiftRows(unsigned char state[4][4]);
            void InvShiftRows(unsigned char state[4][4]);

            unsigned char xtime(unsigned char b);    // multiply on x

            void MixColumns(unsigned char state[4][4]);
            void InvMixColumns(unsigned char state[4][4]);

            void AddRoundKey(unsigned char state[4][4], unsigned char *key);

            void SubWord(unsigned char *a);
            void RotWord(unsigned char *a);
            void XorWords(unsigned char *a, unsigned char *b, unsigned char *c);
            void Rcon(unsigned char * a, int n);
            void KeyExpansion(unsigned char *key);

            void XorBlocks(unsigned char *a, unsigned char * b, unsigned char *c, unsigned int len);

        public:

            /// encrypts a fixed 16 byte block from `src` into `dest` | param types : [unsigned char*/Krypt::Bytes*]
            void EncryptBlock(Bytes *in, Bytes *out);

            /// decrypts a fixed 16 byte block from `src` into `dest` | param types : [unsigned char*/Krypt::Bytes*]
            void DecryptBlock(Bytes *in, Bytes *out);

            /// initialize the round key from a key
            void setKey(Bytes* key, size_t keyLen);
            AES(Bytes* ByteArray, size_t keyLen);
            ~AES();
    };
}

#include "blockcipher/AES/setkey.cpp"
#include "blockcipher/AES/cipher_block.cpp"
#include "blockcipher/AES/key_expansion.cpp"
#include "blockcipher/AES/add_roundkey.cpp"
#include "blockcipher/AES/mix_columns.cpp"
#include "blockcipher/AES/shift_rows.cpp"
#include "blockcipher/AES/sub_bytes.cpp"

#endif