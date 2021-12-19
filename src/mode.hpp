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
            BlockCipher::BASE_BLOCKCIPHER* Encryption;
            Padding::ZeroNulls* PaddingScheme;

            MODE()
            {
                Encryption = NULL;
                PaddingScheme = NULL;
            }

            // MODE(size_t blockSize) : Encryption(new CIPHER_TYPE), PaddingScheme(new PADDING_TYPE) {}

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
            ECB(const Bytes* key, size_t keyLen);
            std::pair<Bytes*,size_t> encrypt(Bytes* plain, size_t plainLen) override;
            std::pair<Bytes*,size_t> decrypt(Bytes* cipher, size_t cipherLen) override;
    };

    template<typename CIPHER_TYPE, typename PADDING_TYPE>
    class CBC : public MODE<CIPHER_TYPE,PADDING_TYPE>
    {
        public:
            CBC(const Bytes* key, size_t keyLen, const Bytes* IV);
            std::pair<Bytes*,size_t> encrypt(Bytes* plain, size_t plainLen) override;
            std::pair<Bytes*,size_t> decrypt(Bytes* cipher, size_t cipherLen) override;
    };

    template<typename CIPHER_TYPE, typename PADDING_TYPE>
    class CFB : public MODE<CIPHER_TYPE,PADDING_TYPE>
    {
        public:
            CFB(const Bytes* key, size_t keyLen, const Bytes* IV);
            std::pair<Bytes*,size_t> encrypt(Bytes* plain, size_t plainLen) override;
            std::pair<Bytes*,size_t> decrypt(Bytes* cipher, size_t cipherLen) override;
    };
}

#include "mode/cbc_mode.cpp"
#include "mode/cfb_mode.cpp"
#include "mode/ecb_mode.cpp"

#endif