/*
----------------adler32.h----------------
Author :      Elerias
Date :        10.08.2021
Version :     1.0.1
Description : Implementation of ALDER-32
-----------------------------------------
*/

#ifndef INCLUDED_ADLER32_H
#define INCLUDED_ADLER32_H


#include <stdint.h>

typedef struct {
    uint32_t A;
    uint32_t B;
} ADLER32Context;

void ADLER32Init(ADLER32Context*);                                  // Initialize A and B (to 1 and 0 respectively).
void ADLER32Process(ADLER32Context*, const unsigned char*, int);    // Process n bytes.
void ADLER32GetChecksum(unsigned char [4], const ADLER32Context*);  // Store the 4-byte checksum


#endif
