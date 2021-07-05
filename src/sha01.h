/*
--------------------sha01.h--------------------
Author :      Elerias
Date :        18.04.2021
Version :     1.0
Description : Implementation of SHA-0 and SHA-1
-----------------------------------------------
*/

#ifndef INCLUDED_SHA01_H
#define INCLUDED_SHA01_H


#include <stdint.h>

typedef struct {
    uint32_t H[5];       // Array which will form the digest at the end
    unsigned int bitLen; // Length in bits
    int alg;             // 0 for SHA-0, 1 for SHA-1
} SHA01Context;

void SHA0Init(SHA01Context*);                                                  // Initialize H, bitLen, and set alg to 0;
void SHA1Init(SHA01Context*);                                                  // Initialize H, bitLen, and set alg to 1;
void SHA01ProcessBlock(SHA01Context*, const unsigned char*);                   // Process one complete 64-bytes block.
void SHA01ProcessLastBlock(SHA01Context*, const unsigned char*, unsigned int); // Process the last 64-bytes block. It can be empty (len=0), complete (len=64) or in part full (0 < len < 64).
void SHA01GetDigest(unsigned char [20], const SHA01Context*);                  // Process H and store the 20-bytes digest.


#endif