/*
-------------------md45.h-------------------
Author :      Elerias
Date :        18.04.2021
Version :     1.0
Description : Implementation of MD4 and MD5
--------------------------------------------
*/

#ifndef INCLUDED_MD45_H
#define INCLUDED_MD45_H


#include <stdint.h>

typedef struct {
    uint32_t H[4];       // Array which will form the digest at the end
    unsigned int bitLen; // Length in bits
    int alg;             // 4 for MD4, 5 for MD5
} MD45Context;           // Used for MD4 and MD5

void MD4Init(MD45Context*);                                                  // Initialize H, bitLen, and set alg to 4;
void MD5Init(MD45Context*);                                                  // Initialize H, bitLen, and set alg to 5;
void MD45ProcessBlock(MD45Context*, const unsigned char*);                   // Process one complete 64-bytes block.
void MD45ProcessLastBlock(MD45Context*, const unsigned char*, unsigned int); // Process the last 64-bytes block. It can be empty (len=0), complete (len=64) or in part full (0 < len < 64).
void MD45GetDigest(unsigned char [16], const MD45Context*);                  // Process H and store the 16-bytes digest.


#endif