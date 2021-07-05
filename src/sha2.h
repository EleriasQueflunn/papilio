/*
---------------------sha2.h---------------------
Author :      Elerias
Date :        18.04.2021
Version :     1.0
Description : Implementation of SHA-224, SHA-256
SHA-384, SHA-512, SHA-512/224, SHA-512/256
------------------------------------------------
*/

#ifndef INCLUDED_SHA2_H
#define INCLUDED_SHA2_H


#include <stdint.h>

typedef struct {
    uint32_t H[8];
    unsigned int bitLen; // Length in bits
    int alg;             // 224 for SHA-224, 256 for SHA-256
} SHA2x32Context;

typedef struct {
    uint64_t H[8];
    unsigned int bitLen; // Length in bits
    int alg;             // 384 for SHA-384, 512 for SHA-512, 224 for SHA-512/224, 256 for SHA-512/256
} SHA2x64Context;

void SHA224Init(SHA2x32Context*);
void SHA256Init(SHA2x32Context*);
void SHA384Init(SHA2x64Context*);
void SHA512Init(SHA2x64Context*);
void SHA512_224Init(SHA2x64Context*);
void SHA512_256Init(SHA2x64Context*);

void SHA2x32ProcessBlock(SHA2x32Context*, const unsigned char*);
void SHA2x64ProcessBlock(SHA2x64Context*, const unsigned char*);

void SHA2x32ProcessLastBlock(SHA2x32Context*, const unsigned char*, unsigned int);
void SHA2x64ProcessLastBlock(SHA2x64Context*, const unsigned char*, unsigned int);

void SHA2x32GetDigest(unsigned char*, const SHA2x32Context*);
void SHA2x64GetDigest(unsigned char*, const SHA2x64Context*);


#endif