/*
--------------global.h--------------
Author :      Elerias
Date :        18.04.2021
Version :     1.0
Description : Includes common macros
------------------------------------
*/

#ifndef INCLUDED_GLOBAL_H
#define INCLUDED_GLOBAL_H


#define ROT32L(x, n) ( ((x) << (n)) | ((x) >> (32-(n))) )
#define ROT32R(x, n) ( ((x) >> (n)) | ((x) << (32-(n))) )

#define ROT32L1(x)  ( ((x) <<  1) | ((x) >> 31) )
#define ROT32L2(x)  ( ((x) <<  2) | ((x) >> 30) )
#define ROT32L3(x)  ( ((x) <<  3) | ((x) >> 29) )
#define ROT32L4(x)  ( ((x) <<  4) | ((x) >> 28) )
#define ROT32L5(x)  ( ((x) <<  5) | ((x) >> 27) )
#define ROT32L6(x)  ( ((x) <<  6) | ((x) >> 26) )
#define ROT32L7(x)  ( ((x) <<  7) | ((x) >> 25) )
#define ROT32L8(x)  ( ((x) <<  8) | ((x) >> 24) )
#define ROT32L9(x)  ( ((x) <<  9) | ((x) >> 23) )
#define ROT32L10(x) ( ((x) << 10) | ((x) >> 22) )
#define ROT32L11(x) ( ((x) << 11) | ((x) >> 21) )
#define ROT32L12(x) ( ((x) << 12) | ((x) >> 20) )
#define ROT32L13(x) ( ((x) << 13) | ((x) >> 19) )
#define ROT32L14(x) ( ((x) << 14) | ((x) >> 18) )
#define ROT32L15(x) ( ((x) << 15) | ((x) >> 17) )
#define ROT32L16(x) ( ((x) << 16) | ((x) >> 16) )

#define ROT32R1(x)  ( ((x) >>  1) | ((x) << 31) )
#define ROT32R2(x)  ( ((x) >>  2) | ((x) << 30) )
#define ROT32R3(x)  ( ((x) >>  3) | ((x) << 29) )
#define ROT32R4(x)  ( ((x) >>  4) | ((x) << 28) )
#define ROT32R5(x)  ( ((x) >>  5) | ((x) << 27) )
#define ROT32R6(x)  ( ((x) >>  6) | ((x) << 26) )
#define ROT32R7(x)  ( ((x) >>  7) | ((x) << 25) )
#define ROT32R8(x)  ( ((x) >>  8) | ((x) << 24) )
#define ROT32R9(x)  ( ((x) >>  9) | ((x) << 23) )
#define ROT32R10(x) ( ((x) >> 10) | ((x) << 22) )
#define ROT32R11(x) ( ((x) >> 11) | ((x) << 21) )
#define ROT32R12(x) ( ((x) >> 12) | ((x) << 20) )
#define ROT32R13(x) ( ((x) >> 13) | ((x) << 19) )
#define ROT32R14(x) ( ((x) >> 14) | ((x) << 18) )
#define ROT32R15(x) ( ((x) >> 15) | ((x) << 17) )
#define ROT32R16(x) ( ((x) >> 16) | ((x) << 16) )


#define ROT64L(x, n) ( ((x) << (n)) | ((x) >> (64-(n))) )
#define ROT64R(x, n) ( ((x) >> (n)) | ((x) << (64-(n))) )

#define ROT64L1(x)  ( ((x) <<  1) | ((x) >> 63) )
#define ROT64L2(x)  ( ((x) <<  2) | ((x) >> 62) )
#define ROT64L3(x)  ( ((x) <<  3) | ((x) >> 61) )
#define ROT64L4(x)  ( ((x) <<  4) | ((x) >> 60) )
#define ROT64L5(x)  ( ((x) <<  5) | ((x) >> 59) )
#define ROT64L6(x)  ( ((x) <<  6) | ((x) >> 58) )
#define ROT64L7(x)  ( ((x) <<  7) | ((x) >> 57) )
#define ROT64L8(x)  ( ((x) <<  8) | ((x) >> 56) )
#define ROT64L9(x)  ( ((x) <<  9) | ((x) >> 55) )
#define ROT64L10(x) ( ((x) << 10) | ((x) >> 54) )
#define ROT64L11(x) ( ((x) << 11) | ((x) >> 53) )
#define ROT64L12(x) ( ((x) << 12) | ((x) >> 52) )
#define ROT64L13(x) ( ((x) << 13) | ((x) >> 51) )
#define ROT64L14(x) ( ((x) << 14) | ((x) >> 50) )
#define ROT64L15(x) ( ((x) << 15) | ((x) >> 49) )
#define ROT64L16(x) ( ((x) << 16) | ((x) >> 48) )
#define ROT64L17(x) ( ((x) << 17) | ((x) >> 47) )
#define ROT64L18(x) ( ((x) << 18) | ((x) >> 46) )
#define ROT64L19(x) ( ((x) << 19) | ((x) >> 45) )
#define ROT64L20(x) ( ((x) << 20) | ((x) >> 44) )
#define ROT64L21(x) ( ((x) << 21) | ((x) >> 43) )
#define ROT64L22(x) ( ((x) << 22) | ((x) >> 42) )
#define ROT64L23(x) ( ((x) << 23) | ((x) >> 41) )
#define ROT64L24(x) ( ((x) << 24) | ((x) >> 40) )
#define ROT64L25(x) ( ((x) << 25) | ((x) >> 39) )
#define ROT64L26(x) ( ((x) << 26) | ((x) >> 38) )
#define ROT64L27(x) ( ((x) << 27) | ((x) >> 37) )
#define ROT64L28(x) ( ((x) << 28) | ((x) >> 36) )
#define ROT64L29(x) ( ((x) << 29) | ((x) >> 35) )
#define ROT64L30(x) ( ((x) << 30) | ((x) >> 34) )
#define ROT64L31(x) ( ((x) << 31) | ((x) >> 33) )
#define ROT64L32(x) ( ((x) << 32) | ((x) >> 32) )

#define ROT64R1(x)  ( ((x) >>  1) | ((x) << 63) )
#define ROT64R2(x)  ( ((x) >>  2) | ((x) << 62) )
#define ROT64R3(x)  ( ((x) >>  3) | ((x) << 61) )
#define ROT64R4(x)  ( ((x) >>  4) | ((x) << 60) )
#define ROT64R5(x)  ( ((x) >>  5) | ((x) << 59) )
#define ROT64R6(x)  ( ((x) >>  6) | ((x) << 58) )
#define ROT64R7(x)  ( ((x) >>  7) | ((x) << 57) )
#define ROT64R8(x)  ( ((x) >>  8) | ((x) << 56) )
#define ROT64R9(x)  ( ((x) >>  9) | ((x) << 55) )
#define ROT64R10(x) ( ((x) >> 10) | ((x) << 54) )
#define ROT64R11(x) ( ((x) >> 11) | ((x) << 53) )
#define ROT64R12(x) ( ((x) >> 12) | ((x) << 52) )
#define ROT64R13(x) ( ((x) >> 13) | ((x) << 51) )
#define ROT64R14(x) ( ((x) >> 14) | ((x) << 50) )
#define ROT64R15(x) ( ((x) >> 15) | ((x) << 49) )
#define ROT64R16(x) ( ((x) >> 16) | ((x) << 48) )
#define ROT64R17(x) ( ((x) >> 17) | ((x) << 47) )
#define ROT64R18(x) ( ((x) >> 18) | ((x) << 46) )
#define ROT64R19(x) ( ((x) >> 19) | ((x) << 45) )
#define ROT64R20(x) ( ((x) >> 20) | ((x) << 44) )
#define ROT64R21(x) ( ((x) >> 21) | ((x) << 43) )
#define ROT64R22(x) ( ((x) >> 22) | ((x) << 42) )
#define ROT64R23(x) ( ((x) >> 23) | ((x) << 41) )
#define ROT64R24(x) ( ((x) >> 24) | ((x) << 40) )
#define ROT64R25(x) ( ((x) >> 25) | ((x) << 39) )
#define ROT64R26(x) ( ((x) >> 26) | ((x) << 38) )
#define ROT64R27(x) ( ((x) >> 27) | ((x) << 37) )
#define ROT64R28(x) ( ((x) >> 28) | ((x) << 36) )
#define ROT64R29(x) ( ((x) >> 29) | ((x) << 35) )
#define ROT64R30(x) ( ((x) >> 30) | ((x) << 34) )
#define ROT64R31(x) ( ((x) >> 31) | ((x) << 33) )
#define ROT64R32(x) ( ((x) >> 32) | ((x) << 32) )

#define CH(x, y, z)     ( ((x) & (y)) | ((~x) & (z)) )
// Equivalent to ( ((x) & (y)) ^ ((~x) & (z)) )
#define MAJ(x, y, z)    ( ((x) & (y)) | ((x) & (z)) | ((y) & (z)) )
// Equivalent to ( ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)) )
#define PARITY(x, y, z) ( (x) ^ (y) ^ (z) )

#define MD4_KA  0x67452301 // Initial constant of the register A in MD4, also used in MD5, SHA0 and SHA1
#define MD4_KB  0xefcdab89 // "
#define MD4_KC  0x98badcfe // "
#define MD4_KD  0x10325476 // "
#define SHA0_KE 0xc3d2e1f0 // Initial constant of the register E in SHA-0, also used in SHA1

// Transform 4 unsigned char variables into a 32-bit word using little indian convention
#define ENCODE32LI(x, a, b, c, d) \
    {x = (uint32_t)(a) | ( ((uint32_t)(b)) << 8 ) | ( ((uint32_t)(c)) << 16 ) | ( ((uint32_t)(d)) << 24 );}

// Transform 4 unsigned char variables into a 32-bit word using big indian convention
#define ENCODE32BI(x, a, b, c, d) \
    ENCODE32LI(x, d, c, b, a)

// Transform a 32-bit word into 4 unsigned char variables using little indian convention
#define DECODE32LI(a, b, c, d, x) \
    { \
        a = (unsigned char) ((x) & 0xff); \
        b = (unsigned char) ( ((x) >>  8) & 0xff ); \
        c = (unsigned char) ( ((x) >> 16) & 0xff ); \
        d = (unsigned char) ( ((x) >> 24) & 0xff ); \
    }

// Transform a 32-bit word into 4 unsigned char variables using big indian convention
#define DECODE32BI(a, b, c, d, x) \
    DECODE32LI(d, c, b, a, x)

// Transform 8 unsigned char variables into a 64-bit word using little indian convention
#define ENCODE64LI(x, a, b, c, d, e, f, g, h) \
    {x = (uint64_t)(a) | ( ((uint64_t)(b)) << 8 ) | ( ((uint64_t)(c)) << 16 ) | ( ((uint64_t)(d)) << 24 ) | ( ((uint64_t)(e)) << 32 ) | ( ((uint64_t)(f)) << 40 ) | ( ((uint64_t)(g)) << 48 ) | ( ((uint64_t)(h)) << 56 );}

// Transform 8 unsigned char variables into a 64-bit word using big indian convention
#define ENCODE64BI(x, a, b, c, d, e, f, g, h) \
    ENCODE64LI(x, h, g, f, e, d, c, b, a)

// Transform a 64-bit word into 8 unsigned char variables using little indian convention
#define DECODE64LI(a, b, c, d, e, f, g, h, x) \
    { \
        a = (unsigned char) ((x) & 0xff); \
        b = (unsigned char) ( ((x) >>  8) & 0xff ); \
        c = (unsigned char) ( ((x) >> 16) & 0xff ); \
        d = (unsigned char) ( ((x) >> 24) & 0xff ); \
        e = (unsigned char) ( ((x) >> 32) & 0xff ); \
        f = (unsigned char) ( ((x) >> 40) & 0xff ); \
        g = (unsigned char) ( ((x) >> 48) & 0xff ); \
        h = (unsigned char) ( ((x) >> 56) & 0xff ); \
    }

// Transform a 64-bit word into 8 unsigned char variables using big indian convention
#define DECODE64BI(a, b, c, d, e, f, g, h, x) \
    DECODE64LI(h, g, f, e, d, c, b, a, x)


#endif