/*
--------------hash.h--------------
Author :      Elerias
Date :        05.08.2021
Version :     1.0.1
Description : Hash function using
----------------------------------
*/

#ifndef INCLUDED_HASH_H
#define INCLUDED_HASH_H


#include <stdio.h>

typedef struct
{
    char name[16];                  // Name of the hash function.
    unsigned int blockSize;         // Block size in bytes.
    unsigned int digestSize;        // Digest size in bytes.
    void* context;                  // Context pointer
    void (*hashInit)();             // Function which inits the hash structure.
    void (*hashProcessBlock)();     // Function which processes a block and tranforms the hash data.
    void (*hashProcessLastBlock)(); // Function which processes the last block and tranforms the hash data.
    void (*hashGetDigest)();        // Function which processes the hash structure and puts the digest in the first parameter.
} HashFunction;

typedef struct
{
    HashFunction* hf;
    int nWords;
    char* preimages;
    int* correctPreimages;
    unsigned char** digests;
    int success;
    char* buffer;
    unsigned char* digest;
    int verbose;
} HashCrackParameters;
 
int setHashFunction(HashFunction*, const char*);                                // Configure HashFunction parameters (name, blockSize ...), return 1 if name is not an implemented hash function else 0.
void hashText(unsigned char*, const HashFunction*, const char*, unsigned int);  // Hash a text.
void hashFile(unsigned char*, const HashFunction*, FILE*);                      // Hash a file.
int hashCrackBruteForce(HashCrackParameters*);                                  // Try preimage attacks by brute force.


#endif
