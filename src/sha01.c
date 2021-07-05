/*
--------------------sha01.c--------------------
Author :      Elerias
Date :        18.04.2021
Version :     0.8
Description : Implementation of SHA-0 and SHA-1
-----------------------------------------------

Description of SHA-0 : https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/NIST.FIPS.180.pdf
Description of SHA-1 : https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
*/

#include <stdint.h>
#include "sha01.h"
#include "global.h"

void SHA0Init(SHA01Context* context)
// Initialize H, bitLen, and set alg to 0;
{
    context->H[0] = MD4_KA;
    context->H[1] = MD4_KB;
    context->H[2] = MD4_KC;
    context->H[3] = MD4_KD;
    context->H[4] = SHA0_KE;
    context->bitLen = 0;
    context->alg = 0;
}

void SHA1Init(SHA01Context* context)
// Initialize H, bitLen, and set alg to 1;
{
    context->H[0] = MD4_KA;
    context->H[1] = MD4_KB;
    context->H[2] = MD4_KC;
    context->H[3] = MD4_KD;
    context->H[4] = SHA0_KE;
    context->bitLen = 0;
    context->alg = 1;
}

void SHA01ProcessBlock(SHA01Context* context, const unsigned char* block)
// Process one complete 64 bytes block.
{
    context->bitLen += 512;
    uint32_t X[80];
    
    for (int k=0 ; k<16 ; k++)
    {
        ENCODE32BI(X[k], block[k*4], block[k*4+1], block[k*4+2], block[k*4+3])
    }
    if (context->alg) // SHA-1
    {
        for (int k=16 ; k<80 ; k++)
        {
            X[k] = ROT32L1(X[k-3] ^ X[k-8] ^ X[k-14] ^ X[k-16]);
        }
    }
    else // SHA-0
    {
        for (int k=16 ; k<80 ; k++)
        {
            X[k] = X[k-3] ^ X[k-8] ^ X[k-14] ^ X[k-16];
        }
    }

    uint32_t a = context->H[0];
    uint32_t b = context->H[1];
    uint32_t c = context->H[2];
    uint32_t d = context->H[3];
    uint32_t e = context->H[4];
    uint32_t t;
    
    int k=0;
    
    while (k<20)
    {
        t = ROT32L5(a) + CH(b, c, d) + e + 0x5a827999 + X[k++];
        e = d; d = c; c = ROT32R2(b); b = a; a = t;
    }
    while (k<40)
    {
        t = ROT32L5(a) + PARITY(b, c, d) + e + 0x6ed9eba1 + X[k++];
        e = d; d = c; c = ROT32R2(b); b = a; a = t;
    }
    while (k<60)
    {
        t = ROT32L5(a) + MAJ(b, c, d) + e + 0x8f1bbcdc + X[k++];
        e = d; d = c; c = ROT32R2(b); b = a; a = t;
    }
    while (k<80)
    {
        t = ROT32L5(a) + PARITY(b, c, d) + e + 0xca62c1d6 + X[k++];
        e = d; d = c; c = ROT32R2(b); b = a; a = t;
    }

    context->H[0] += a;
    context->H[1] += b;
    context->H[2] += c;
    context->H[3] += d;
    context->H[4] += e;
}

void SHA01ProcessLastBlock(SHA01Context* context, const unsigned char* lastBlock, unsigned int len)
// Process the last 64-bytes block. It can be empty (len=0), complete (len=64) or in part full (0 < len < 64).
{
    unsigned char block[64];
    if (len == 64)
    {
        SHA01ProcessBlock(context, lastBlock);
        len = 0;
    }
    context->bitLen += len*8;

    for (unsigned int k=0 ; k<len ; k++)
    {
        block[k] = lastBlock[k];
    }
    block[len] = 0b10000000; // Byte padding
    if (len >= 56)
    {
        for (unsigned int k=len+1 ; k<64 ; k++)
        {
            block[k] = 0;
        }
        SHA01ProcessBlock(context, block);
        context->bitLen -= 512;
        for (int k=0 ; k<56 ; k++)
        {
            block[k] = 0;
        }
    }
    else
    {
        for (unsigned int k=len+1 ; k<56 ; k++)
        {
            block[k] = 0;
        }
    }
    DECODE64BI(block[56], block[57], block[58], block[59], block[60], block[61], block[62], block[63], ((uint64_t) context->bitLen))
    SHA01ProcessBlock(context, block);
}

void SHA01GetDigest(unsigned char* digest, const SHA01Context* context)
// Process H and store the 20-bytes digest.
{
    for (int k=0 ; k<5 ; k++)
    {
        DECODE32BI(digest[k*4], digest[k*4+1], digest[k*4+2], digest[k*4+3], context->H[k])
    }
}