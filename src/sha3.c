/*
----------------------sha3.c----------------------
Author :      Elerias
Date :        05.05.2021
Version :     0.8
Description : Implementation of SHA3-224, SHA3-256
SHA3-384, SHA3-512, SHAKE128, SHAKE256
--------------------------------------------------

Description of SHA-3 : https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
*/

#include <stdio.h>
#include <stdint.h>
#include "sha3.h"
#include "global.h"

static void keccakF1600(SHA3Context*);
static void SHA3Init(SHA3Context*, int, int);

/* Definition of rc(t) and RC in python3
def rc(t):
    R = [1, 0, 0, 0, 0, 0, 0, 0]
    for k in range(t):
        R = [0] + R
        R[0] ^= R[8]
        R[4] ^= R[8]
        R[5] ^= R[8]
        R[6] ^= R[8]
        R = R[:-1]
    return R[0]

RC = []
for i in range(24):
    n = 0
    for j in range(7):
        n += T[j+7*i] << (2**j-1)
    RC.append(n)
*/

static const uint64_t RC[24] =
{0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
 0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
 0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
 0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
 0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

void printContext(SHA3Context* context)
{
    for (int x=0 ; x<5 ; x++) printf("%019lu %019lu %019lu %019lu %019lu\n", context->H[x][0], context->H[x][1], context->H[x][2], context->H[x][3], context->H[x][4]);
    unsigned char a, b, c, d, e, f, g, h;
    int i = 1;
    for (int k=0 ; k<25 ; k++)
    {
        DECODE64LI(a, b, c, d, e, f, g, h, context->H[k%5][k/5])
        if (i)
        {
            printf("%02x %02x %02x %02x %02x %02x %02x %02x ", a, b, c, d, e, f, g, h);
        }
        else
        {
            printf("%02x %02x %02x %02x %02x %02x %02x %02x\n", a, b, c, d, e, f, g, h);
        }
        i = 1-i;
    }
    printf("\n");
}

static void keccakF1600(SHA3Context* context)
{
    uint64_t P[5];
    uint64_t a, b;
    int x, y;
    for (int i=0 ; i<24 ; i++)
    {
        // Theta
        for (x=0 ; x<5 ; x++)
        {
            P[x] = context->H[x][0] ^ context->H[x][1] ^ context->H[x][2] ^ context->H[x][3] ^ context->H[x][4];
        }
        for (x=0 ; x<5 ; x++)
        {
            a = P[(x+4)%5] ^ ROT64L1(P[(x+1)%5]);
            for (y=0 ; y<5 ; y++)
            {
                context->H[x][y] ^= a;
            }
        }

        // Rho + Pi
        x = 1;
        y = 0;
        b = context->H[x][y];
        for (int k=0 ; k<24 ; k++)
        {
            a = x;
            x = y;
            y = (2*a + 3*y) % 5;
            a = context->H[x][y];
            context->H[x][y] = ROT64L(b, (((k+1)*(k+2)) >> 1) & 63);
            b = a;
        }

        // Chi
        for (y=0 ; y<5 ; y++)
        {
            a = context->H[0][y] ^ ( ~context->H[1][y] & context->H[2][y] );
            b = context->H[1][y] ^ ( ~context->H[2][y] & context->H[3][y] );
            context->H[2][y] ^= ~context->H[3][y] & context->H[4][y];
            context->H[3][y] ^= ~context->H[4][y] & context->H[0][y];
            context->H[4][y] ^= ~context->H[0][y] & context->H[1][y];
            context->H[0][y] = a;
            context->H[1][y] = b;
        }

        // Iota
        context->H[0][0] ^= RC[i];
    }
}

#define C(context) ((context)->alg / 32)     // capacity in blocks of 64 bits
#define R(context) (25 - C(context))         // rate = block size in blocks of 64 bits
#define BLOCKSIZE(context) (8 * R(context))  // block size in bytes

static void SHA3Init(SHA3Context* context, int alg, int shake)
{
    for (int i=0 ; i<5 ; i++)
    {
        for (int j=0 ; j<5 ; j++)
        {
            context->H[i][j] = 0;
        }
    }
    context->alg = alg;
    context->shake = shake;
}

void SHA3_224Init(SHA3Context* context)
{
    SHA3Init(context, 224, 0);
}

void SHA3_256Init(SHA3Context* context)
{
    SHA3Init(context, 256, 0);
}

void SHA3_384Init(SHA3Context* context)
{
    SHA3Init(context, 384, 0);
}

void SHA3_512Init(SHA3Context* context)
{
    SHA3Init(context, 512, 0);
}

void SHAKE128Init(SHA3Context* context, int digestSize)
{
    SHA3Init(context, 128, digestSize);
}

void SHAKE256Init(SHA3Context* context, int digestSize) // digestSize in bytes
{
    SHA3Init(context, 256, digestSize);
}

void SHA3ProcessBlock(SHA3Context* context, const unsigned char* block)
{
    {
        uint64_t P;
        for (int k=0 ; k<R(context) ; k++)
        {
            ENCODE64LI(P, block[k*8],  block[k*8+1],  block[k*8+2],  block[k*8+3],  block[k*8+4],  block[k*8+5],  block[k*8+6],  block[k*8+7])
            context->H[k%5][k/5] ^= P;
        }
    }

    keccakF1600(context);
}

void SHA3ProcessLastBlock(SHA3Context* context, const unsigned char* lastBlock, unsigned int len)
{
    unsigned char block[200];
    if (len == BLOCKSIZE(context))
    {
        SHA3ProcessBlock(context, lastBlock);
        len = 0;
    }
    for (unsigned int k=0 ; k<len ; k++)
    {
        block[k] = lastBlock[k];
    }
    block[len++] = (context->shake) ? 0x1f : 0x06; // padding
    while (len < BLOCKSIZE(context))
    {
        block[len++] = 0;
    }
    block[len-1] ^= 0x80;
    SHA3ProcessBlock(context, block);
}

void SHA3GetDigest(unsigned char* digest, const SHA3Context* context)
{
    char T[8];
    if (context->shake)
    {
        int k;
        for (k=0 ; k<context->shake/8 ; k++)
        {
            DECODE64LI(digest[k*8], digest[k*8+1], digest[k*8+2], digest[k*8+3], digest[k*8+4], digest[k*8+5], digest[k*8+6], digest[k*8+7], context->H[k%5][k/5])
        }
        DECODE64LI(T[0], T[1], T[2], T[3], T[4], T[5], T[6], T[7], context->H[k%5][k/5])
        k*=8;
        for (int i=0 ; i<context->shake-k ; i++)
        {
            digest[k+i] = T[i];
        }
    }
    else
    {
        for (int k=0 ; k<context->alg / 64 ; k++)
        {
            DECODE64LI(digest[k*8], digest[k*8+1], digest[k*8+2], digest[k*8+3], digest[k*8+4], digest[k*8+5], digest[k*8+6], digest[k*8+7], context->H[k%5][k/5])
        }
        if (context->alg == 224)
        {
            DECODE64LI(digest[24], digest[25], digest[26], digest[27], T[0], T[1], T[2], T[3], context->H[3][0])
        }
    }
}