/*
-------------func.c-------------
Author :      Elerias
Date :        06.08.2021
Version :     1.0
Description : Diverse functions
--------------------------------
*/


#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "hash.h"
#include "global.h"


void printBytesInHexa(const unsigned char* bytes, int len)
// Print array in hexadecimal
{
    while (len--)
        printf("%02x", *bytes++);
}

int hexaToBytes(unsigned char* bytes, int bytesLen, const char* hexa_str)
// Convert an hexadecimal string (ex : "a5fe34") to an array of bytes. hexa_str length has to be equals to bytesLen.
{
    int hexaLen = strlen(hexa_str);
    if (hexaLen != 2*bytesLen)
        return 2*bytesLen - hexaLen;
    
    unsigned int c;
    while (bytesLen--)
    {
        if (!isxdigit(*hexa_str) || !isxdigit(hexa_str[1]))
            return 1000;
        sscanf(hexa_str, "%02x", &c);
        *bytes = (unsigned char) c;
        hexa_str += 2;
        ++bytes;
    }
    
    return 0;
}
    
void bytesToHexa(char* hexa_str, const unsigned char* bytes, int bytesLen)
// Convert an array of bytes to an hexadecimal string
{
    while (bytesLen--)
    {
        sprintf(hexa_str, "%02x", *bytes);
        hexa_str += 2;
        ++bytes;
    }
    *hexa_str = 0;
}

int strcmpdiff(char* diff, const char* s1, const char* s2)
// Compare two strings, return 0 if they are equals else write their difference and return the number of different characters.
{
    int b=0;

    while (*s1 && *s2)
    {
        if (*s1++ != *s2++)
        {
            ++b;
            *diff++ = '*';
        }
        else
        {
            *diff++ = ' ';
        }
    }
    
    while (*s1++)
    {
        ++b;
        *diff++ = '*';
    }
    while (*s2++)
    {
        ++b;
        *diff++ = '*';
    }
    
    *diff = 0;

    return b;
}

int isDigest(const char* msg, int digestSize)
{
    while ( isxdigit(*msg++) && digestSize)
        --digestSize;
    return (digestSize == 0);
}
    
