#ifndef AES_BLOCK_ENCRYPTION_USING_SIMD_AES_INSTRUCTION
#define AES_BLOCK_ENCRYPTION_USING_SIMD_AES_INSTRUCTION

// Dec-23-2021

/* ====================== CONTENTS ======================

Byte == unsigned char

bool AESNI_IS_AVAILABLE();
void AesBlockEncrypt(Byte* plain, Byte* cipher, Byte* roundKeys, int Nr, int Nb)
void AesBlockDecrypt(Byte* cipher, Byte* recover, Byte* roundKeys, int Nr, int Nb)

   ======================================================
*/

#include <stdio.h>
#include <immintrin.h>
#include <bitset>

// ------------------------- REFERENCE START -------------------------

// https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
// Before an application attempts to use the AES instructions, it should verify that the
// processor supports these instructions. This should be done by checking that
// CPUID.01H:ECX.AES[bit 25] = 1. The following (assembly) code demonstrates this
// check. 

// GCC

#define cpuid(func,ax,bx,cx,dx) \
    __asm__ __volatile__ ("cpuid":\
    "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));

int Check_CPU_support_AES()
{
    unsigned int a,b,c,d;
    cpuid(1, a,b,c,d);
    return (c & 0x2000000);
}

inline __m128i AES_128_ASSIST (__m128i temp1, __m128i temp2)
{
    __m128i temp3;
    temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
    temp3 = _mm_slli_si128 (temp1, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp1 = _mm_xor_si128 (temp1, temp2);
    return temp1;
}

// -------------------------  REFERENCE END  -------------------------

bool AESNI_IS_AVAILABLE()
{
    std::bitset<32> ecx(Check_CPU_support_AES());
    return ecx[25];
}

// compile with -maes flag for gcc

typedef unsigned char Byte;

void AesBlockEncrypt(Byte* plain, Byte* cipher, Byte* roundKeys, int Nr, int Nb)
{
    // load the current block & current round key into the registers
    __m128i state = _mm_loadu_si128((__m128i*)plain);
    __m128i crkey = _mm_loadu_si128((__m128i*)roundKeys);

    // first round
    state = _mm_xor_si128(state, crkey);

    // next rounds
    for(int round = 1; round <= Nr - 1; ++round)
    {
        crkey = _mm_loadu_si128((__m128i*)(roundKeys+(round*4*Nb)));
        state = _mm_aesenc_si128(state,crkey);
    }

    // last round
    crkey = _mm_loadu_si128((__m128i*)(roundKeys+(Nr*4*Nb)));
    state = _mm_aesenclast_si128(state, crkey);

    // store from register to array
    _mm_storeu_si128((__m128i*)(cipher),state);
}

/** Note:
 * The aes instruction uses “Inverse Cipher” for decryption, meaning it does not use the original round keys for decryption.
 * Instead it uses the “Equivalent Inverse Cipher” for decryption where InverseMixColumns is applied on the original round keys.
 **/
void AesBlockDecrypt(Byte* cipher, Byte* recover, Byte* roundKeys, int Nr, int Nb)
{
    // load the current block & current round key into the registers
    __m128i state = _mm_loadu_si128((__m128i*)cipher);
    __m128i crkey = _mm_loadu_si128((__m128i*)(roundKeys+(Nr*4*Nb)));

    // first round
    state = _mm_xor_si128(state, crkey);

    // next rounds
    for(int round = Nr-1; round >= 1; --round)
    {
        crkey = _mm_loadu_si128((__m128i*)(roundKeys+(round*4*Nb)));

        // you can optimized this by generating the invmix of the reversed round keys before hand
        // that way you don't need to call the function _mm_aesimc_si128
        crkey = _mm_aesimc_si128(crkey);

        state = _mm_aesdec_si128(state,crkey);
    }

    // last round
    crkey = _mm_loadu_si128((__m128i*)roundKeys);
    state = _mm_aesdeclast_si128(state, crkey);

    // store from register to array
    _mm_storeu_si128((__m128i*)recover,state);
}

// you can even optimized these two functions further by unrolling the "next rounds" for loop

#endif