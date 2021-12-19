#ifndef KRYPT_FUNCTIONS_HPP
#define KRYPT_FUNCTIONS_HPP

#include <iostream>
#include "types.hpp"

namespace Krypt
{
    Bytes xtime(Bytes b);    // multiply on x
    void SubWord(Bytes *a);
    void RotWord(Bytes *a);
    void XorWords(Bytes *a, Bytes *b, Bytes *c);
    void XorBlocks(unsigned char *a, unsigned char * b, unsigned char *c, unsigned int len);
    void Rcon(Bytes * a, int n);
    void printHexArray (unsigned char a[], size_t n);
    void printHexVector (const std::vector<unsigned char>& a);
    std::vector<unsigned char> ArrayToVector(unsigned char *a, unsigned char len);
    const unsigned char *VectorToArray(const std::vector<unsigned char>& a);
}

#include "functions.cpp"

#endif