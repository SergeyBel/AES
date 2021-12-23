#ifndef KRYPT_BLOCKCIPHER_HPP
#define KRYPT_BLOCKCIPHER_HPP

#include <iostream>
#include <cstring>
#include <exception>
#include "types.hpp"
#include "functions.hpp"

namespace Krypt::BlockCipher
{
    class BASE_BLOCKCIPHER
    {
        public:
            //  BLOCK_SIZE IN BYTES
            size_t BLOCK_SIZE;
            Bytes *IV;

            BASE_BLOCKCIPHER(size_t blockSize) : BLOCK_SIZE(blockSize) {}

            virtual void EncryptBlock(Bytes*, Bytes*) {};
            virtual void DecryptBlock(Bytes*, Bytes*) {};

            void setIV(const Bytes* iv);

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

            void KeyExpansion(const Bytes* key);

            inline void SubBytes(unsigned char state[4][4]);
            inline void InvSubBytes(unsigned char state[4][4]);

            inline void ShiftRows(unsigned char state[4][4]);
            inline void InvShiftRows(unsigned char state[4][4]);

            inline void MixColumns(unsigned char state[4][4]);
            inline void InvMixColumns(unsigned char state[4][4]);

            void AddRoundKey(unsigned char state[4][4], unsigned char *key);

        public:

            /// encrypts a fixed 16 byte block from `src` into `dest` | param types : [unsigned char*/Krypt::Bytes*]
            void EncryptBlock(Bytes *src, Bytes *dest) override;

            /// decrypts a fixed 16 byte block from `src` into `dest` | param types : [unsigned char*/Krypt::Bytes*]
            void DecryptBlock(Bytes *src, Bytes *dest) override;

            /// initialize the round key from a key
            void setKey(const Bytes* key, size_t keyLen);
            AES(const Bytes* ByteArray, size_t keyLen);
            AES(const Bytes* ByteArray, size_t keyLen, const Bytes* IV);
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
