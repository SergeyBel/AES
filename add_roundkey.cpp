#ifndef ADD_ROUND_KEY_CPP
#define ADD_ROUND_KEY_CPP

#include "AES.h"

namespace Cipher
{
    void AES::AddRoundKey(unsigned char state[4][4], unsigned char *key)
    {
        int i, j;
        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < Nb; j++)
            {
                state[i][j] = state[i][j] ^ key[i + 4 * j];
            }
        }
    }
}

#endif