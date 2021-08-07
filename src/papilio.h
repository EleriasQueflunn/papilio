/*
--------------papilio.h--------------
Author :      Elerias
Date :        06.08.2021
Version :     1.1
Description : Hash functions library
-------------------------------------
*/

#ifndef INCLUDED_PAPILIO_H
#define INCLUDED_PAPILIO_H


int helpCommand();            // Print papilio help message
int hCommand(int, char**);    // Calculate the hash values of specified messages
int hfCommand(int, char**);   // Calculate the hash values of specified files
int hcCommand(int, char**);   // Try preimage attacks by brute force
int cmpCommand(int, char**);  // Check the digest of a message
int cmpfCommand(int, char**); // Check the digest of a file or verify if the two files have the same digest


#endif
