/*
-------------func.h-------------
Author :      Elerias
Date :        06.08.2021
Version :     1.0
Description : Diverse functions
--------------------------------
*/ 

#ifndef INCLUDED_FUNC_H
#define INCLUDED_FUNC_H


void printBytesInHexa(const unsigned char*, int);    // Print array in hexadecimal
int hexaToBytes(unsigned char*, int, const char*);   // Convert an hexadecimal string (ex : "a5fe34") to an array of bytes. hexa_str length has to be equals to bytesLen.
void bytesToHexa(char*, const unsigned char*, int);  // Convert an array of bytes to an hexadecimal string
int strcmpdiff(char*, const char*, const char*);     // Compare two strings, return 0 if they are equals else 1 and write their difference.
int isDigest(const char*, int);


#endif
