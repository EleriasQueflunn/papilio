/*
----------------adler32.c----------------
Author :      Elerias
Date :        10.08.2021
Version :     0.8.1
Description : Implementation of ALDER-32
-----------------------------------------
*/

#include <stdint.h>
#include "adler32.h"
#include "global.h"

void ADLER32Init(ADLER32Context* context)
// Initialize A and B (to 1 and 0 respectively)
{
    context->A = 1;
    context->B = 0;
}

void ADLER32Process(ADLER32Context* context, const unsigned char* bytes, int n)
// Process n bytes
{
    while (n--)
    {
        context->A = (context->A + (uint32_t) *bytes++) % 65521;
        context->B = (context->B + context->A) % 65521;
    }
}

void ADLER32GetChecksum(unsigned char checksum[4], const ADLER32Context* context)
// Store the 4-byte checksum
{
    uint32_t C = context->B << 16 | context->A;
    DECODE32BI(checksum[0], checksum[1], checksum[2], checksum[3], C)
}
