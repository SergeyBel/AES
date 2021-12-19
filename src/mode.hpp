#ifndef KRYPT_MODE_OF_ENCRYPTION_HPP
#define KRYPT_MODE_OF_ENCRYPTION_HPP

#include <iostream>
#include "types.hpp"
#include "blockcipher.hpp"
#include "padding.hpp"

namespace Krypt::Mode
{
    template<typename CIPHER_TYPE, typename PADDING_TYPE>
    class MODE
    {
        public:
            size_t BLOCK_SIZE;
            BlockCipher::BASE_BLOCKCIPHER* Encryption;
            Padding::ZeroNulls* PaddingScheme;

            MODE()
            {
                BLOCK_SIZE = 0;
                Encryption = NULL;
                PaddingScheme = NULL;
            }

            MODE(size_t blockSize) : BLOCK_SIZE(blockSize), Encryption(new CIPHER_TYPE), PaddingScheme(new PADDING_TYPE) {}

            virtual std::pair<Bytes*,size_t> encrypt(Bytes*, size_t) { return {NULL,0}; }
            virtual std::pair<Bytes*,size_t> decrypt(Bytes*, size_t) { return {NULL,0}; }

            ~MODE()
            {
                delete Encryption;
                delete PaddingScheme;
            }
    };

    template<typename CIPHER_TYPE, typename PADDING_TYPE>
    class ECB : public MODE<CIPHER_TYPE,PADDING_TYPE>
    {
        public:
            ECB(const Sequence& key);
            std::pair<Bytes*,size_t> encrypt(Bytes* plain, size_t plainLen) override;
            std::pair<Bytes*,size_t> decrypt(Bytes* cipher, size_t cipherLen) override;
    };

    template<typename CIPHER_TYPE, typename PADDING_TYPE>
    class CBC : public MODE<CIPHER_TYPE,PADDING_TYPE>
    {
        public:
            CBC(const Sequence& key);
            std::pair<Bytes*,size_t> encrypt(Bytes* plain, size_t plainLen) override;
            std::pair<Bytes*,size_t> decrypt(Bytes* cipher, size_t cipherLen) override;
    };

    template<typename CIPHER_TYPE, typename PADDING_TYPE>
    class CFB : public MODE<CIPHER_TYPE,PADDING_TYPE>
    {
        public:
            CFB(const Sequence& key);
            std::pair<Bytes*,size_t> encrypt(Bytes* plain, size_t plainLen) override;
            std::pair<Bytes*,size_t> decrypt(Bytes* cipher, size_t cipherLen) override;
    };
}

#include "mode/cbc_mode.cpp"
#include "mode/cfb_mode.cpp"
#include "mode/ecb_mode.cpp"

#endif