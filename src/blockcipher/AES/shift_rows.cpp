#ifndef SHIFT_ROWS_CPP
#define SHIFT_ROWS_CPP

#include "../../blockcipher.hpp"

namespace Krypt::BlockCipher
{
    void AES::ShiftRows(unsigned char state[4][4])
    {
        //row 2
        unsigned char buffer = state[1][0];
        memmove(state[1],state[1]+1,sizeof(unsigned char)*3);
        state[1][3] = buffer;

        // row 3
        unsigned char thrid[2];
        memcpy(thrid,state[2],sizeof(unsigned char)*2);
        memcpy(state[2],state[2]+2,sizeof(unsigned char)*2);
        memcpy(state[2]+2,thrid,sizeof(unsigned char)*2);

        // row 4
        buffer = state[3][3];
        memmove(state[3]+1,state[3],sizeof(unsigned char)*3);
        state[3][0] = buffer;
    }

    void AES::InvShiftRows(unsigned char state[4][4])
    {
        //row 2
        unsigned char buffer = state[1][3];
        memmove(state[1]+1,state[1],sizeof(unsigned char)*3);
        state[1][0] = buffer;

        // row 3
        unsigned char thrid[2];
        memcpy(thrid,state[2],sizeof(unsigned char)*2);
        memcpy(state[2],state[2]+2,sizeof(unsigned char)*2);
        memcpy(state[2]+2,thrid,sizeof(unsigned char)*2);

        // row 4
        buffer = state[3][0];
        memmove(state[3],state[3]+1,sizeof(unsigned char)*3);
        state[3][3] = buffer;
    }
}

#endif