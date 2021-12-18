#ifndef KEY_EXPANSION_CPP
#define KEY_EXPANSION_CPP

#include "../../blockcipher.hpp"

namespace Krypt
{
    unsigned char AES::xtime(unsigned char b)    // multiply on x
    {
        return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
    }

    void AES::SubWord(unsigned char *a)
    {
        int i;
        for (i = 0; i < 4; i++)
        {
            a[i] = sbox[a[i]];
        }
    }

    void AES::RotWord(unsigned char *a)
    {
        unsigned char c = a[0];
        a[0] = a[1];
        a[1] = a[2];
        a[2] = a[3];
        a[3] = c;
    }

    void AES::XorWords(unsigned char *a, unsigned char *b, unsigned char *c)
    {
        int i;
        for (i = 0; i < 4; i++)
        {
            c[i] = a[i] ^ b[i];
        }
    }

    void AES::Rcon(unsigned char * a, int n)
    {
        int i;
        unsigned char c = 1;
        for (i = 0; i < n - 1; i++)
        {
            c = xtime(c);
        }

        a[0] = c;
        a[1] = a[2] = a[3] = 0;
    }

    void AES::KeyExpansion(unsigned char *key)
    {
        unsigned char *w = new unsigned char[4 * Nb * (Nr + 1)];
        unsigned char *temp = new unsigned char[4];
        unsigned char *rcon = new unsigned char[4];

        int i = 0;
        while (i < 4 * Nk)
        {
            w[i] = key[i];
            i++;
        }

        i = 4 * Nk;
        while (i < 4 * Nb * (Nr + 1))
        {
            temp[0] = w[i - 4 + 0];
            temp[1] = w[i - 4 + 1];
            temp[2] = w[i - 4 + 2];
            temp[3] = w[i - 4 + 3];

            if (i / 4 % Nk == 0)
            {
                RotWord(temp);
                SubWord(temp);
                Rcon(rcon, i / (Nk * 4));
                XorWords(temp, rcon, temp);
            }
            else if (Nk > 6 && i / 4 % Nk == 4)
            {
                SubWord(temp);
            }

            w[i + 0] = w[i - 4 * Nk] ^ temp[0];
            w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
            w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
            w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
            i += 4;
        }

        delete []rcon;
        delete []temp;

        RoundedKeys = w;
    }

    // void AES::KeyExpansion(unsigned char key[])
    // {
    //     unsigned char *w = new unsigned char[4 * Nb * (Nr + 1)];
    //     unsigned char *temp = new unsigned char[4];
    //     unsigned char *rcon = new unsigned char[4];

    //     int i = 0;
    //     while (i < 4 * Nk)
    //     {
    //         w[i] = key[i];
    //         i++;
    //     }

    //     i = 4 * Nk;
    //     while (i < 4 * Nb * (Nr + 1))
    //     {
    //         temp[0] = w[i - 4 + 0];
    //         temp[1] = w[i - 4 + 1];
    //         temp[2] = w[i - 4 + 2];
    //         temp[3] = w[i - 4 + 3];

    //         if (i / 4 % Nk == 0)
    //         {
    //             RotWord(temp);
    //             SubWord(temp);
    //             Rcon(rcon, i / (Nk * 4));
    //             XorWords(temp, rcon, temp);
    //         }
    //         else if (Nk > 6 && i / 4 % Nk == 4)
    //         {
    //             SubWord(temp);
    //         }

    //         w[i + 0] = w[i - 4 * Nk] ^ temp[0];
    //         w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
    //         w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
    //         w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
    //         i += 4;
    //     }

    //     delete []rcon;
    //     delete []temp;

    //     RoundedKeys = w;
    // }
}

#endif