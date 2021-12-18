#ifndef MODE
#define MDOE

#include <iostream>
#include "types.hpp"

template<typename BLOCK_CIPHER, typename PADDING>
class MODE
{
    public:

        BLOCK_CIPHER* BlockCipher;
        PADDING* PaddingScheme;

        virtual Krypt::Bytes* encrypt() {};
        virtual Krypt::Bytes* decrypt() {};
};

template<typename BLOCK_CIPHER, typename PADDING>
class ECB : public MODE
{
    public:
        virtual Krypt::Bytes* encrypt() {};
        virtual Krypt::Bytes* decrypt() {};
};

template<typename BLOCK_CIPHER, typename PADDING>
class CBC : public MODE
{
    public:
        virtual Krypt::Bytes* encrypt() {};
        virtual Krypt::Bytes* decrypt() {};
};

template<typename BLOCK_CIPHER, typename PADDING>
class CFB : public MODE
{
    public:
        virtual Krypt::Bytes* encrypt() {};
        virtual Krypt::Bytes* decrypt() {};
};

#endif