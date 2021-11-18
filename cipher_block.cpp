#ifndef CIPHER_BLOCK_CPP
#define CIPHER_BLOCK_CPP

#include "AES.h"

namespace Cipher
{
    unsigned char * AES::PaddingNulls(unsigned char in[], unsigned int inLen, unsigned int alignLen)
    {
        unsigned char *alignIn = new unsigned char[alignLen];
        memcpy(alignIn, in, inLen);
        memset(alignIn + inLen, 0x00, alignLen - inLen);
        return alignIn;
    }

    unsigned int AES::GetPaddingLength(unsigned int len)
    {
        unsigned int lengthWithPadding =  (len / blockBytesLen);
        if (len % blockBytesLen) {
            lengthWithPadding++;
        }
        
        lengthWithPadding *=  blockBytesLen;
        
        return lengthWithPadding;
    }

    void AES::EncryptBlock(unsigned char in[], unsigned char out[], unsigned  char *roundKeys)
    {
        unsigned char state[4][4];
        int i, j, round;

        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < Nb; j++)
            {
                state[i][j] = in[i + 4 * j];
            }
        }

        AddRoundKey(state, roundKeys);

        for (round = 1; round <= Nr - 1; round++)
        {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, roundKeys + round * 4 * Nb);
        }

        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, roundKeys + Nr * 4 * Nb);

        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < Nb; j++)
            {
                out[i + 4 * j] = state[i][j];
            }
        }
    }

    void AES::DecryptBlock(unsigned char in[], unsigned char out[], unsigned  char *roundKeys)
    {
        unsigned char state[4][4];
        int i, j, round;

        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < Nb; j++) {
                state[i][j] = in[i + 4 * j];
            }
        }

        AddRoundKey(state, roundKeys + Nr * 4 * Nb);

        for (round = Nr - 1; round >= 1; round--)
        {
            InvSubBytes(state);
            InvShiftRows(state);
            AddRoundKey(state, roundKeys + round * 4 * Nb);
            InvMixColumns(state);
        }

        InvSubBytes(state);
        InvShiftRows(state);
        AddRoundKey(state, roundKeys);

        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < Nb; j++) {
                out[i + 4 * j] = state[i][j];
            }
        }
    }
}

#endif