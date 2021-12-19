#ifndef KRYPT_FUNCTIONS_HPP
#define KRYPT_FUNCTIONS_HPP

#include <iostream>
#include "types.hpp"

namespace Krypt
{
    inline Bytes xtime(Bytes b);    // multiply on x
    inline void SubWord(Bytes *a);
    inline void RotWord(Bytes *a);
    inline void XorWords(Bytes *a, Bytes *b, Bytes *c);
    inline void XorBlocks(unsigned char *a, unsigned char * b, unsigned char *c, unsigned int len);
    
    void Rcon(Bytes * a, int n);
    void printHexArray (unsigned char a[], size_t n);
    void printHexVector (const std::vector<unsigned char>& a);
    std::vector<unsigned char> ArrayToVector(unsigned char *a, unsigned char len);
    const unsigned char *VectorToArray(const std::vector<unsigned char>& a);
}

#include "functions.cpp"

#endif