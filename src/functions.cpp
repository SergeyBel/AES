#ifndef KRYPT_FUNCTIONS_CPP
#define KRYPT_FUNCTIONS_CPP

#include "functions.hpp"

namespace Krypt
{
    Bytes xtime(Bytes b)    // multiply on x
    {
        return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
    }

    void SubWord(Bytes *a)
    {
        int i;
        for (i = 0; i < 4; i++)
        {
            a[i] = sbox[a[i]];
        }
    }

    void RotWord(Bytes *a)
    {
        Bytes c = a[0];
        a[0] = a[1];
        a[1] = a[2];
        a[2] = a[3];
        a[3] = c;
    }

    void XorWords(Bytes *a, Bytes *b, Bytes *c)
    {
        int i;
        for (i = 0; i < 4; i++)
        {
            c[i] = a[i] ^ b[i];
        }
    }

    void XorBlocks(unsigned char *a, unsigned char * b, unsigned char *c, unsigned int len)
    {
        for (unsigned int i = 0; i < len; i++)
        {
            c[i] = a[i] ^ b[i];
        }
    }

    void Rcon(Bytes * a, int n)
    {
        int i;
        Bytes c = 1;
        for (i = 0; i < n - 1; i++)
        {
            c = xtime(c);
        }

        a[0] = c;
        a[1] = a[2] = a[3] = 0;
    }

    void printHexArray (unsigned char a[], size_t n)
    {
        for (size_t i = 0; i < n; i++) {
            printf("%02x ", a[i]);
        }
        std::cout << "\n";
    }

    void printHexVector (const std::vector<unsigned char>& a)
    {
        for (size_t i = 0; i < a.size(); i++) {
            printf("%02x ", a[i]);
        }
    }

    std::vector<unsigned char> ArrayToVector(unsigned char *a, unsigned char len)
    {
        std::vector<unsigned char> v(a, a + len * sizeof(unsigned char));
        return v;
    }

    const unsigned char *VectorToArray(const std::vector<unsigned char>& a)
    {
        return a.data();
    }
}

#endif