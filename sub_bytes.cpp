#ifndef SUB_BYTES_CPP
#define SUB_BYTES_CPP

#include "AES.h"

namespace Cipher
{
    void AES::SubBytes(unsigned char state[4][4])
    {
        int i, j;
        unsigned char t;
        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < Nb; j++)
            {
                t = state[i][j];
                state[i][j] = sbox[t / 16][t % 16];
            }
        }
    }

    void AES::InvSubBytes(unsigned char state[4][4])
    {
        int i, j;
        unsigned char t;
        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < Nb; j++)
            {
                t = state[i][j];
                state[i][j] = inv_sbox[t / 16][t % 16];
            }
        }
    }
}

#endif