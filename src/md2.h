/*
---------------md2.h---------------
Author :      Elerias
Date :        17.04.2021
Version :     1.0
Description : Implementation of MD2
-----------------------------------
*/

#ifndef INCLUDED_MD2_H
#define INCLUDED_MD2_H


typedef struct {
    unsigned char H[48]; // Array whose 16 first bytes will form the digest at the end
    unsigned char C[16]; // Checksum
} MD2Context;

void MD2Init(MD2Context*);                                                 // Initialize H and C (to 0).
void MD2ProcessBlock(MD2Context*, const unsigned char*);                   // Process one complete 16-bytes block.
void MD2ProcessLastBlock(MD2Context*, const unsigned char*, unsigned int); // Process the last 16-bytes block. It can be empty (len=0), complete (len=16) or in part full (0 < len < 16).
void MD2GetDigest(unsigned char [16], const MD2Context*);                  // Process H and store the 16-bytes digest


#endif