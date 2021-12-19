#ifndef KRYPT_BLOCKCIPHER_HPP
#define KRYPT_BLOCKCIPHER_HPP

#include <iostream>
#include <cstring>
#include "types.hpp"

namespace Krypt::BlockCipher
{
    class BASE_BLOCKCIPHER
    {
        public:
            //  BLOCK_SIZE IN BYTES
            size_t BLOCK_SIZE;

            BASE_BLOCKCIPHER(size_t blockSize) : BLOCK_SIZE(blockSize) {}

            virtual void EncryptBlock(Bytes*, Bytes*) {};
            virtual void DecryptBlock(Bytes*, Bytes*) {};
            virtual ~BASE_BLOCKCIPHER() = default;
    };

    /// @def AES BLOCK CIPHER, ENCRYPTION - DECRYPTION OF 16 BYTES BLOCK
    class AES : public BASE_BLOCKCIPHER
    {
        private:
            
            const static size_t Nb = 4;
            size_t Nk;
            size_t Nr;
            Bytes *RoundedKeys;

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
            void KeyExpansion(const Bytes* key);

            void XorBlocks(unsigned char *a, unsigned char * b, unsigned char *c, unsigned int len);

        public:

            /// encrypts a fixed 16 byte block from `src` into `dest` | param types : [unsigned char*/Krypt::Bytes*]
            void EncryptBlock(Bytes *src, Bytes *dest) override;

            /// decrypts a fixed 16 byte block from `src` into `dest` | param types : [unsigned char*/Krypt::Bytes*]
            void DecryptBlock(Bytes *src, Bytes *dest) override;

            /// initialize the round key from a key
            void setKey(const Bytes* key, size_t keyLen);
            AES(const Bytes* ByteArray, size_t keyLen);
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