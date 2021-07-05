/*
-------------------md45.c-------------------
Author :      Elerias
Date :        18.04.2021
Version :     0.8
Description : Implementation of MD4 and MD5
--------------------------------------------

Description of MD4 : https://tools.ietf.org/html/rfc1320
Description of MD5 : https://tools.ietf.org/html/rfc1321
*/

#include <stdint.h>
#include "md45.h"
#include "global.h"

// MD4fRN is the function used at the round N in MD4
#define MD4fR1(a, b, c, d, x, s) {(a) = ROT32L((a) + CH(b,c,d) + (x), s);}
#define MD4fR2(a, b, c, d, x, s) {(a) = ROT32L((a) + MAJ(b,c,d) + (x) + (uint32_t) 0x5a827999, s);}
#define MD4fR3(a, b, c, d, x, s) {(a) = ROT32L((a) + PARITY(b,c,d) + (x) + (uint32_t) 0x6ed9eba1, s);}

#define MD4R1(a, b, c, d, X) \
    { \
        MD4fR1(a, b, c, d, X[ 0],  3); \
        MD4fR1(d, a, b, c, X[ 1],  7); \
        MD4fR1(c, d, a, b, X[ 2], 11); \
        MD4fR1(b, c, d, a, X[ 3], 19); \
        MD4fR1(a, b, c, d, X[ 4],  3); \
        MD4fR1(d, a, b, c, X[ 5],  7); \
        MD4fR1(c, d, a, b, X[ 6], 11); \
        MD4fR1(b, c, d, a, X[ 7], 19); \
        MD4fR1(a, b, c, d, X[ 8],  3); \
        MD4fR1(d, a, b, c, X[ 9],  7); \
        MD4fR1(c, d, a, b, X[10], 11); \
        MD4fR1(b, c, d, a, X[11], 19); \
        MD4fR1(a, b, c, d, X[12],  3); \
        MD4fR1(d, a, b, c, X[13],  7); \
        MD4fR1(c, d, a, b, X[14], 11); \
        MD4fR1(b, c, d, a, X[15], 19); \
    }

#define MD4R2(a, b, c, d, X) \
    { \
        MD4fR2(a, b, c, d, X[ 0],  3); \
        MD4fR2(d, a, b, c, X[ 4],  5); \
        MD4fR2(c, d, a, b, X[ 8],  9); \
        MD4fR2(b, c, d, a, X[12], 13); \
        MD4fR2(a, b, c, d, X[ 1],  3); \
        MD4fR2(d, a, b, c, X[ 5],  5); \
        MD4fR2(c, d, a, b, X[ 9],  9); \
        MD4fR2(b, c, d, a, X[13], 13); \
        MD4fR2(a, b, c, d, X[ 2],  3); \
        MD4fR2(d, a, b, c, X[ 6],  5); \
        MD4fR2(c, d, a, b, X[10],  9); \
        MD4fR2(b, c, d, a, X[14], 13); \
        MD4fR2(a, b, c, d, X[ 3],  3); \
        MD4fR2(d, a, b, c, X[ 7],  5); \
        MD4fR2(c, d, a, b, X[11],  9); \
        MD4fR2(b, c, d, a, X[15], 13); \
    }

#define MD4R3(a, b, c, d, X) \
    { \
        MD4fR3(a, b, c, d, X[ 0],  3); \
        MD4fR3(d, a, b, c, X[ 8],  9); \
        MD4fR3(c, d, a, b, X[ 4], 11); \
        MD4fR3(b, c, d, a, X[12], 15); \
        MD4fR3(a, b, c, d, X[ 2],  3); \
        MD4fR3(d, a, b, c, X[10],  9); \
        MD4fR3(c, d, a, b, X[ 6], 11); \
        MD4fR3(b, c, d, a, X[14], 15); \
        MD4fR3(a, b, c, d, X[ 1],  3); \
        MD4fR3(d, a, b, c, X[ 9],  9); \
        MD4fR3(c, d, a, b, X[ 5], 11); \
        MD4fR3(b, c, d, a, X[13], 15); \
        MD4fR3(a, b, c, d, X[ 3],  3); \
        MD4fR3(d, a, b, c, X[11],  9); \
        MD4fR3(c, d, a, b, X[ 7], 11); \
        MD4fR3(b, c, d, a, X[15], 15); \
    }

    
#define I(X, Y, Z) ((Y) ^ ((X) | (~Z)))

#define MD5fR1(a, b, c, d, x, s, i) {(a) = (b) + ROT32L((a) + CH(b,c,d) + (x) + (i), s);}
#define MD5fR2(a, b, c, d, x, s, i) {(a) = (b) + ROT32L((a) + CH(d,b,c) + (x) + (i), s);}
#define MD5fR3(a, b, c, d, x, s, i) {(a) = (b) + ROT32L((a) + PARITY(b,c,d) + (x) + (i), s);}
#define MD5fR4(a, b, c, d, x, s, i) {(a) = (b) + ROT32L((a) + I(b,c,d) + (x) + (i), s);}

#define MD5R1(a, b, c, d, X) \
    { \
        MD5fR1(a, b, c, d, X[ 0],  7, 0xd76aa478); \
        MD5fR1(d, a, b, c, X[ 1], 12, 0xe8c7b756); \
        MD5fR1(c, d, a, b, X[ 2], 17, 0x242070db); \
        MD5fR1(b, c, d, a, X[ 3], 22, 0xc1bdceee); \
        MD5fR1(a, b, c, d, X[ 4],  7, 0xf57c0faf); \
        MD5fR1(d, a, b, c, X[ 5], 12, 0x4787c62a); \
        MD5fR1(c, d, a, b, X[ 6], 17, 0xa8304613); \
        MD5fR1(b, c, d, a, X[ 7], 22, 0xfd469501); \
        MD5fR1(a, b, c, d, X[ 8],  7, 0x698098d8); \
        MD5fR1(d, a, b, c, X[ 9], 12, 0x8b44f7af); \
        MD5fR1(c, d, a, b, X[10], 17, 0xffff5bb1); \
        MD5fR1(b, c, d, a, X[11], 22, 0x895cd7be); \
        MD5fR1(a, b, c, d, X[12],  7, 0x6b901122); \
        MD5fR1(d, a, b, c, X[13], 12, 0xfd987193); \
        MD5fR1(c, d, a, b, X[14], 17, 0xa679438e); \
        MD5fR1(b, c, d, a, X[15], 22, 0x49b40821); \
    }

#define MD5R2(a, b, c, d, X) \
    { \
        MD5fR2(a, b, c, d, X[ 1],  5, 0xf61e2562); \
        MD5fR2(d, a, b, c, X[ 6],  9, 0xc040b340); \
        MD5fR2(c, d, a, b, X[11], 14, 0x265e5a51); \
        MD5fR2(b, c, d, a, X[ 0], 20, 0xe9b6c7aa); \
        MD5fR2(a, b, c, d, X[ 5],  5, 0xd62f105d); \
        MD5fR2(d, a, b, c, X[10],  9,  0x2441453); \
        MD5fR2(c, d, a, b, X[15], 14, 0xd8a1e681); \
        MD5fR2(b, c, d, a, X[ 4], 20, 0xe7d3fbc8); \
        MD5fR2(a, b, c, d, X[ 9],  5, 0x21e1cde6); \
        MD5fR2(d, a, b, c, X[14],  9, 0xc33707d6); \
        MD5fR2(c, d, a, b, X[ 3], 14, 0xf4d50d87); \
        MD5fR2(b, c, d, a, X[ 8], 20, 0x455a14ed); \
        MD5fR2(a, b, c, d, X[13],  5, 0xa9e3e905); \
        MD5fR2(d, a, b, c, X[ 2],  9, 0xfcefa3f8); \
        MD5fR2(c, d, a, b, X[ 7], 14, 0x676f02d9); \
        MD5fR2(b, c, d, a, X[12], 20, 0x8d2a4c8a); \
    }

#define MD5R3(a, b, c, d, X) \
    { \
        MD5fR3(a, b, c, d, X[ 5],  4, 0xfffa3942); \
        MD5fR3(d, a, b, c, X[ 8], 11, 0x8771f681); \
        MD5fR3(c, d, a, b, X[11], 16, 0x6d9d6122); \
        MD5fR3(b, c, d, a, X[14], 23, 0xfde5380c); \
        MD5fR3(a, b, c, d, X[ 1],  4, 0xa4beea44); \
        MD5fR3(d, a, b, c, X[ 4], 11, 0x4bdecfa9); \
        MD5fR3(c, d, a, b, X[ 7], 16, 0xf6bb4b60); \
        MD5fR3(b, c, d, a, X[10], 23, 0xbebfbc70); \
        MD5fR3(a, b, c, d, X[13],  4, 0x289b7ec6); \
        MD5fR3(d, a, b, c, X[ 0], 11, 0xeaa127fa); \
        MD5fR3(c, d, a, b, X[ 3], 16, 0xd4ef3085); \
        MD5fR3(b, c, d, a, X[ 6], 23,  0x4881d05); \
        MD5fR3(a, b, c, d, X[ 9],  4, 0xd9d4d039); \
        MD5fR3(d, a, b, c, X[12], 11, 0xe6db99e5); \
        MD5fR3(c, d, a, b, X[15], 16, 0x1fa27cf8); \
        MD5fR3(b, c, d, a, X[ 2], 23, 0xc4ac5665); \
    }

#define MD5R4(a, b, c, d, X) \
    { \
        MD5fR4(a, b, c, d, X[ 0],  6, 0xf4292244); \
        MD5fR4(d, a, b, c, X[ 7], 10, 0x432aff97); \
        MD5fR4(c, d, a, b, X[14], 15, 0xab9423a7); \
        MD5fR4(b, c, d, a, X[ 5], 21, 0xfc93a039); \
        MD5fR4(a, b, c, d, X[12],  6, 0x655b59c3); \
        MD5fR4(d, a, b, c, X[ 3], 10, 0x8f0ccc92); \
        MD5fR4(c, d, a, b, X[10], 15, 0xffeff47d); \
        MD5fR4(b, c, d, a, X[ 1], 21, 0x85845dd1); \
        MD5fR4(a, b, c, d, X[ 8],  6, 0x6fa87e4f); \
        MD5fR4(d, a, b, c, X[15], 10, 0xfe2ce6e0); \
        MD5fR4(c, d, a, b, X[ 6], 15, 0xa3014314); \
        MD5fR4(b, c, d, a, X[13], 21, 0x4e0811a1); \
        MD5fR4(a, b, c, d, X[ 4],  6, 0xf7537e82); \
        MD5fR4(d, a, b, c, X[11], 10, 0xbd3af235); \
        MD5fR4(c, d, a, b, X[ 2], 15, 0x2ad7d2bb); \
        MD5fR4(b, c, d, a, X[ 9], 21, 0xeb86d391); \
    }

void MD4Init(MD45Context* context)
// Initialize H, bitLen, and set alg to 4;
{
    // Constants defined in global.h
    context->H[0] = MD4_KA;
    context->H[1] = MD4_KB;
    context->H[2] = MD4_KC;
    context->H[3] = MD4_KD;
    context->bitLen = 0;
    context->alg = 4;
}

void MD5Init(MD45Context* context)
// Initialize H, bitLen, and set alg to 5;
{
    // Constants defined in global.h
    context->H[0] = MD4_KA;
    context->H[1] = MD4_KB;
    context->H[2] = MD4_KC;
    context->H[3] = MD4_KD;
    context->bitLen = 0;
    context->alg = 5;
}

void MD45ProcessBlock(MD45Context* context, const unsigned char* block)
// Process one complete 64 bytes block.
{
    context->bitLen += 512;
    uint32_t X[16];
    
    for (int k=0 ; k<16 ; k++)
    {
        ENCODE32LI(X[k], block[k*4], block[k*4+1], block[k*4+2], block[k*4+3])
    }

    uint32_t a = context->H[0];
    uint32_t b = context->H[1];
    uint32_t c = context->H[2];
    uint32_t d = context->H[3];
    
    if (context->alg - 4)
    {
        MD5R1(a, b, c, d, X)
        MD5R2(a, b, c, d, X)
        MD5R3(a, b, c, d, X)
        MD5R4(a, b, c, d, X)
    }
    else
    {
        MD4R1(a, b, c, d, X)
        MD4R2(a, b, c, d, X)
        MD4R3(a, b, c, d, X)
    }

    context->H[0] += a;
    context->H[1] += b;
    context->H[2] += c;
    context->H[3] += d;
}

void MD45ProcessLastBlock(MD45Context* context, const unsigned char* lastBlock, unsigned int len)
// Process the last 64-bytes block. It can be empty (len=0), complete (len=64) or in part full (0 < len < 64).
{
    unsigned char block[64];
    if (len == 64)
    {
        MD45ProcessBlock(context, lastBlock);
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
        MD45ProcessBlock(context, block);
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
    DECODE64LI(block[56], block[57], block[58], block[59], block[60], block[61], block[62], block[63], ((uint64_t) context->bitLen))
    MD45ProcessBlock(context, block);
}

void MD45GetDigest(unsigned char* digest, const MD45Context* context)
// Process H and store the 16-bytes digest in digest.
{
    for (unsigned int k=0 ; k<4 ; k++)
    {
        DECODE32LI(digest[k*4], digest[k*4+1], digest[k*4+2], digest[k*4+3], context->H[k])
    }
}