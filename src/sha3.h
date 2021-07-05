/*
----------------------sha3.h----------------------
Author :      Elerias
Date :        05.05.2021
Version :     1.0
Description : Implementation of SHA3-224, SHA3-256
SHA3-384, SHA3-512, SHAKE128, SHAKE256
--------------------------------------------------
*/

#ifndef INCLUDED_SHA3_H
#define INCLUDED_SHA3_H


#include <stdint.h>

typedef struct {
    uint64_t H[5][5];  // A 5x5 square of 64 bits (lines of size 5, columns of size 5, lanes of size 64)
    int alg;           // 224 for SHA3-224, 256 for SHA3-256, 384 for SHA3-384, 512 for SHA3-512
    int shake;         // 0 if SHA, digestSize in bits if SHAKE
} SHA3Context;

void SHA3_224Init(SHA3Context*);
void SHA3_256Init(SHA3Context*);
void SHA3_384Init(SHA3Context*);
void SHA3_512Init(SHA3Context*);
void SHAKE128Init(SHA3Context*, int);
void SHAKE256Init(SHA3Context*, int);
void SHA3ProcessBlock(SHA3Context*, const unsigned char*);
void SHA3ProcessLastBlock(SHA3Context*, const unsigned char*, unsigned int);
void SHA3GetDigest(unsigned char*, const SHA3Context*);


#endif