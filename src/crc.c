/*
-----------------crc.c-----------------
Author :      Elerias
Date :        10.08.2021
Version :     0.8
Description : Implementation of CRC-32
(IEEE) and CRC-64
---------------------------------------
*/

#include <stdio.h>
#include "crc.h"
#include "global.h"

#define LSBCRC32Polynomial 0xedb88320
#define MSBCRC64EPolynomial 0x42f0e1eba9ea3693
#define LSBCRC64IPolynomial 0xd800000000000000

static uint32_t CRC32Table[256];
static int CRC32TableIsInitialized = 0;

void CRC32Init(CRC32Context* rem)
// Initialize the reminder to -1 (0xffffffff) and the lookup table
{
    *rem = 0xffffffff;

    if (!CRC32TableIsInitialized)
    {
        uint32_t temp;
        for (int i=0 ; i < 256 ; ++i)
        {
            temp = (uint32_t) i;
            for (int j=0 ; j < 8 ; ++j)
                if (temp & 1)
                    temp = temp >> 1 ^ LSBCRC32Polynomial;
                else
                    temp >>= 1;
            CRC32Table[i] = temp;
        }
        CRC32TableIsInitialized = 1;
    }
}

void CRC32Process(CRC32Context* rem, const unsigned char* bytes, int n)
// Process n bytes
{
    while (n--)
        *rem = *rem >> 8 ^ CRC32Table[(*rem & 0xff) ^ (uint32_t) *bytes++];
}

void CRC32GetChecksum(unsigned char checksum[4], const CRC32Context* rem)
// Store the 4-byte checksum
{
    DECODE32BI(checksum[0], checksum[1], checksum[2], checksum[3], ~*rem)
}

static uint64_t CRC64ETable[256];
static int CRC64ETableIsInitialized = 0;

void CRC64EInit(CRC64Context* rem)
// Initialize the reminder to 0 and the lookup table
{
    *rem = 0;

    if (!CRC64ETableIsInitialized)
    {
        uint64_t temp;
        for (int i=0 ; i < 256 ; ++i)
        {
            temp = (uint64_t) i << 56;
            for (int j=0 ; j < 8 ; ++j)
                if (temp & 0x8000000000000000)
                    temp = temp << 1 ^ MSBCRC64EPolynomial;
                else
                    temp <<= 1;
            CRC64ETable[i] = temp;
        }
        CRC64ETableIsInitialized = 1;
    }
}

void CRC64EProcess(CRC64Context* rem, const unsigned char* bytes, int n)
// Process n bytes
{
    while (n--)
        *rem = *rem << 8 ^ CRC64ETable[*rem >> 56 ^ (uint64_t) *bytes++];
}

void CRC64EGetChecksum(unsigned char checksum[8], const CRC64Context* rem)
// Store the 4-byte checksum
{
    DECODE64BI(checksum[0], checksum[1], checksum[2], checksum[3], checksum[4], checksum[5], checksum[6], checksum[7], *rem)
}

static uint64_t CRC64ITable[256];
static int CRC64ITableIsInitialized = 0;

void CRC64IInit(CRC64Context* rem)
// Initialize the reminder to -1 (0xffffffffffffffff) and the lookup table
{
    *rem = 0xffffffffffffffff;

    if (!CRC64ITableIsInitialized)
    {
        uint64_t temp;
        for (int i=0 ; i < 256 ; ++i)
        {
            temp = (uint64_t) i;
            for (int j=0 ; j < 8 ; ++j)
                if (temp & 1)
                    temp = temp >> 1 ^ LSBCRC64IPolynomial;
                else
                    temp >>= 1;
            CRC64ITable[i] = temp;
        }
        CRC64ITableIsInitialized = 1;
    }
}

void CRC64IProcess(CRC64Context* rem, const unsigned char* bytes, int n)
// Process n bytes
{
    while (n--)
        *rem = *rem >> 8 ^ CRC64ITable[(*rem & 0xff) ^ (uint64_t) *bytes++];
}

void CRC64IGetChecksum(unsigned char checksum[8], const CRC64Context* rem)
// Store the 4-byte checksum
{
    DECODE64BI(checksum[0], checksum[1], checksum[2], checksum[3], checksum[4], checksum[5], checksum[6], checksum[7], ~*rem)
}
