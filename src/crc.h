/*
-----------------crc.h-----------------
Author :      Elerias
Date :        10.08.2021
Version :     1.0
Description : Implementation of CRC-32
(IEEE) and CRC-64
---------------------------------------
*/

#ifndef INCLUDED_CRC_H
#define INCLUDED_CRC_H


#include <stdint.h>

typedef uint32_t CRC32Context;

void CRC32Init(CRC32Context*);                                 // Initialize the reminder to -1 (0xffffffff) and the lookup table
void CRC32Process(CRC32Context*, const unsigned char*, int);   // Process n bytes
void CRC32GetChecksum(unsigned char [4], const CRC32Context*); // Store the 4-byte checksum

typedef uint64_t CRC64Context;

void CRC64EInit(CRC64Context*);                                 // Initialize the reminder to 0 and the lookup table
void CRC64EProcess(CRC64Context*, const unsigned char*, int);   // Process n bytes
void CRC64EGetChecksum(unsigned char [8], const CRC64Context*); // Store the 8-byte checksum

void CRC64IInit(CRC64Context*);                                 // Initialize the reminder to -1 (0xffffffffffffffff) and the lookup table
void CRC64IProcess(CRC64Context*, const unsigned char*, int);   // Process n bytes
void CRC64IGetChecksum(unsigned char [8], const CRC64Context*); // Store the 8-byte checksum


#endif
