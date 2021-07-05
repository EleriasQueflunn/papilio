/*
--------------papilio.c--------------
Author :      Elerias
Date :        05.08.2021
Version :     0.8
Description : Hash functions library
-------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "papilio.h"
#include "hash.h"

int main(int argc, char* argv[])
{
    if ( (argc == 1) || (strcmp("help", argv[1]) == 0) || (strcmp("-h", argv[1]) == 0) || (strcmp("--help", argv[1]) == 0) )
    {
        return helpCommand();
    }
    if (strcmp("h", argv[1]) == 0)
    {
        return hCommand(argc-1, argv+1);
    }
    if (strcmp("hf", argv[1]) == 0)
    {
        return hfCommand(argc-1, argv+1);
    }
    if (strcmp("hc", argv[1]) == 0)
    {
        return hcCommand(argc-1, argv+1);
    }
    printf("papilio : unsupported command : %s\n", argv[1]);
    return 1;
}

int helpCommand()
// Print papilio help message
{
    printf("Papilio 0.8 (05.08.2021)\n");
    printf("Usage :\n");
    printf("  papilio [help|-h|--help]                  Print this help message\n");
    printf("  papilio h <hashfunction> <message>...     Calculate the digest of messages\n");
    printf("  papilio hf <hashfunction> <filename>...   Calculate the digest of files\n");
    printf("  papilio hc <hashfunction> <level> <digest>...     Hash crack : try preimage attacks by brute force\n");
    printf("\n");
    printf("0 <= level <= 5\n");
    printf("0: < 1 s, 1: < 10 s, 2: < 100 s, ...\n");
    printf("Supported hash functions : md2, md4, md5, sha0, sha1, sha2, sha3\n");
    return 0;
}

int hCommand(int argc, char* argv[])
// Calculate the hash values of specified messages
{
    if (argc <= 1)
    {
        printf("papilio : h : no input hash function\n");
        return 1;
    }
    
    HashFunction hf_s;
    HashFunction* hf = &hf_s;
    
    if (setHashFunction(hf, argv[1]))
    {
        printf("papilio : h : not implemented hash function : %s\n", argv[1]);
        return 1;
    }
    if (argc == 2)
    {
        printf("papilio : h : %s : no input message\n", argv[1]);
        return 1;
    }
    
    unsigned char digest[64];
    for (int i=2 ; i<argc ; i++)
    {
         hashText(digest, hf, argv[i], (unsigned int) strlen(argv[i]));
         printf("%s digest of \"%s\" : ", hf->name, argv[i]);
         for (unsigned int j=0 ; j < hf->digestSize ; j++)
         {
             printf("%02x", digest[j]);
         }
         printf("\n");
    }
    return 0;
}

int hfCommand(int argc, char* argv[])
// Calculate the hash values of specified files
{
    if (argc <= 1)
    {
        printf("papilio : hf : no input hash function\n");
        return 1;
    }

    HashFunction hf_s;
    HashFunction* hf = &hf_s;
    
    if (setHashFunction(hf, argv[1]))
    {
        printf("papilio : hf : not implemented hash function : %s\n", argv[1]);
        return 1;
    }
    if (argc == 2)
    {
        printf("papilio : hf : %s : no input file\n", argv[1]);
        return 1;
    }

    unsigned char digest[64];
    FILE* f = NULL;
    for (int i=2 ; i<argc ; i++)
    {
        f = fopen(argv[i], "r");
        if (f == NULL)
        {
            printf("papilio : hf : file not found : \"%s\"\n", argv[i]);
        }
        else
        {
            hashFile(digest, hf, f);
            printf("%s digest of \"%s\" : ", hf->name, argv[i]);
            for (unsigned int j=0 ; j < hf->digestSize ; j++)
            {
                printf("%02x", digest[j]);
            }
            printf("\n");
            fclose(f);
        }
    }
    return 0;
}

int hcCommand(int argc, char* argv[])
{
    if (argc <= 1)
    {
        printf("papilio : hc : no input hash function\n");
        return 1;
    }

    HashFunction hf_s;
    HashFunction* hf = &hf_s;
    
    if (setHashFunction(hf, argv[1]))
    {
        printf("papilio : hc : not implemented hash function : %s\n", argv[1]);
        return 1;
    }
    
    if (argc <= 2)
    {
        printf("papilio : hc : no input level\n");
        return 1;
    }
    
    int level;
    sscanf(argv[2], "%i", &level);
    if (level < 0 || level > 5)
    {
        printf("papilio : hc : incorrect level\n");
        return 1;
    }
    
    if (argc == 3)
    {
        printf("papilio : hc : %s : no input digest\n", argv[1]);
        return 1;
    }
    
    char* preimages = (char*) calloc( (size_t) (16 * (argc-3)), (size_t) 1);
    int* correctPreimages = (int*) calloc( (size_t) (argc-3), sizeof(int));
    unsigned char** digests = (unsigned char**) malloc( (size_t) (argc-3) * sizeof(unsigned char*));
    for (int i=3 ; i<argc ; ++i)
    {
        digests[i-3] = (unsigned char*) malloc( (size_t) hf->digestSize);
        for (int j=0 ; j<hf->digestSize ; ++j)
        {
            digests[i-3][j] = ( (argv[i][j*2] <= 57) ? ( (unsigned char) (argv[i][j*2]-48) )*16 : ( (unsigned char) (argv[i][j*2]-87) )*16 ) + ( (argv[i][j*2+1] <= 57) ? ( (unsigned char) (argv[i][j*2+1]-48) ) : ( (unsigned char) (argv[i][j*2+1]-87) ) );
        }
    }
    
    char buffer[16];
    unsigned char digest[64];
    HashCrackParameters P;
    P.hf = hf;
    P.nWords = argc-3;
    P.preimages = preimages;
    P.correctPreimages = correctPreimages;
    P.digests = digests;
    P.success = 0;
    P.level = level;
    P.buffer = buffer;
    P.digest = digest;
    P.verbose = 1;
    
    hashCrackBruteForce(&P);
    
    for (int i=0 ; i<argc-3 ; i++)
    {
        printf("Preimage of ");
        for (unsigned int j=0 ; j < hf->digestSize ; j++)
        {
            printf("%02x", digests[i][j]);
        }
        printf(" :\n");
        if (P.correctPreimages[i])
        {
            printf("Hexa : ");
            for (int j=0 ; j < (P.correctPreimages[i] == -1 ? 0 : P.correctPreimages[i]) ; j++) 
            {
                printf("%02x", P.preimages[i*16+j]);
            }
            printf("\nAscii : ");
            printf("%s\n", P.preimages+i*16);
        }
        else
        {
            printf("Not found\n");
        }
        free(digests[i]);
    }
    free(digests);
    free(correctPreimages);
    free(preimages);
    
    return 0;
}