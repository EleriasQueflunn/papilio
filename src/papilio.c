/*
--------------papilio.c--------------
Author :      Elerias
Date :        06.08.2021
Version :     0.10
Description : Hash functions library
-------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "papilio.h"
#include "hash.h"
#include "func.h"

int main(int argc, char* argv[])
{
    if ( (argc == 1) || (strcmp("help", argv[1]) == 0) || (strcmp("-h", argv[1]) == 0) || (strcmp("--help", argv[1]) == 0) )
        return helpCommand();

    if (strcmp("h", argv[1]) == 0)
        return hCommand(argc-1, argv+1);

    if (strcmp("hf", argv[1]) == 0)
        return hfCommand(argc-1, argv+1);

    if (strcmp("hc", argv[1]) == 0)
        return hcCommand(argc-1, argv+1);

    if (strcmp("cmp", argv[1]) == 0)
        return cmpCommand(argc-1, argv+1);
    
    if (strcmp("cmpf", argv[1]) == 0)
        return cmpfCommand(argc-1, argv+1);

    printf("papilio : unsupported command : %s\n", argv[1]);

    return 1;
}

int helpCommand()
// Print papilio help message
{
    printf("Papilio 0.10 (06.08.2021)\n");
    printf("Usage :\n");
    printf("  cmp <hashfunction> <message> <digest> Check the digest of a message\n");
    printf("  cmpf <hashfunction> <file> <digest>   Check the digest of a file\n");
    printf("  cmpf <hashfunction> <file> <file>     Verify if the two files have the same digest\n");
    printf("  h <hashfunction> <message>...         Calculate the digest of messages\n");
    printf("  [help|-h|--help]                      Print this help message\n");
    printf("  hf <hashfunction> <filename>...       Calculate the digest of files\n");
    printf("  hc <hashfunction> <digest>...         Hash crack : try preimage attacks by brute force\n");
    printf("\n");
    printf("Supported hash functions : md2, md4, md5, sha0, sha1, sha256, sha512, sha224, sha384, sha512_224, sha512_256, sha3_256, sha3_512, sha3_224, sha3_384\n");
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
        printf("papilio : h : no input message\n");
        return 1;
    }
    
    unsigned char digest[64];
    for (int i=2 ; i<argc ; i++)
    {
         hashText(digest, hf, argv[i], (unsigned int) strlen(argv[i]));
         printf("%s digest of \"%s\" : ", hf->name, argv[i]);
         printBytesInHexa(digest, hf->digestSize);
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
        printf("papilio : hf : no input file\n");
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
            printBytesInHexa(digest, hf->digestSize);
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
    
    if (argc == 2)
    {
        printf("papilio : hc : no input digest\n");
        return 1;
    }
    
    char* preimages = (char*) calloc( (size_t) (16 * (argc-2)), (size_t) 1);
    int* correctPreimages = (int*) calloc( (size_t) (argc-2), sizeof(int));
    unsigned char** digests = (unsigned char**) malloc( (size_t) (argc-2) * sizeof(unsigned char*));
    int n;
    for (int i=2 ; i<argc ; ++i)
    {
        digests[i-2] = (unsigned char*) malloc( (size_t) hf->digestSize);
        if ( (n = hexaToBytes(digests[i-2], hf->digestSize, argv[i])) )
        {
            printf("papilio : hc : %s is not a correct digest for %s function\n", argv[i], argv[1]);
            if (n == 1000)
            {
                printf("All digits are not hexadecimal digits\n");
                return 1;
            }
            if (n < 0)
                printf("%i digits too many\n", -n);
            else
                printf("%i missing digits\n", n);
            return 1;
        }
    }
    
    char buffer[16];
    unsigned char digest[64];
    HashCrackParameters P;
    P.hf = hf;
    P.nWords = argc-2;
    P.preimages = preimages;
    P.correctPreimages = correctPreimages;
    P.digests = digests;
    P.success = 0;
    P.buffer = buffer;
    P.digest = digest;
    P.verbose = 1;
    
    hashCrackBruteForce(&P);
    
    for (int i=0 ; i<argc-2 ; i++)
    {
        printf("Preimage of ");
        printBytesInHexa(digests[i], hf->digestSize);
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

int cmpCommand(int argc, char* argv[])
{
    if (argc <= 1)
    {
        printf("papilio : cmp : no input hash function\n");
        return 1;
    }
    
    HashFunction hf_s;
    HashFunction* hf = &hf_s;
    
    if (setHashFunction(hf, argv[1]))
    {
        printf("papilio : cmp : not implemented hash function : %s\n", argv[1]);
        return 1;
    }
    if (argc == 2)
    {
        printf("papilio : cmp : no input message\n");
        return 1;
    }
    if (argc == 3)
    {
        printf("papilio : cmp : no input digest\n");
        return 1;
    }
    if (argc > 4)
    {
        printf("papilio : cmp : too many arguments : %i instead of 2\n", argc-2);
        return 1;
    }
    
    unsigned char msgDigest[64];
    char msgDigestStr[129];
    char diff[129];
    hashText(msgDigest, hf, argv[2], (unsigned int) strlen(argv[2]));
    bytesToHexa(msgDigestStr, msgDigest, hf->digestSize);
    printf("%s (%s digest of \"%s\")\n", msgDigestStr, hf->name, argv[2]);
    printf("%s (expected digest)\n", argv[3]);
    if (strcmpdiff(diff, msgDigestStr, argv[3]))
        printf("%s (difference)\nNot equal\n", diff);
    else
        printf("Equal\n");

    return 0;
}
    
int cmpfCommand(int argc, char* argv[])
// Check the digest of a file or verify if the two files have the same digest
{
    if (argc <= 1)
    {
        printf("papilio : cmpf : no input hash function\n");
        return 1;
    }
    
    HashFunction hf_s;
    HashFunction* hf = &hf_s;
    
    if (setHashFunction(hf, argv[1]))
    {
        printf("papilio : cmpf : not implemented hash function : %s\n", argv[1]);
        return 1;
    }
    if (argc == 2)
    {
        printf("papilio : cmpf : no input file\n");
        return 1;
    }
    if (argc == 3)
    {
        printf("papilio : cmpf : no input file or digest\n");
        return 1;
    }
    if (argc > 4)
    {
        printf("papilio : cmpf : too many arguments : %i instead of 2\n", argc-2);
        return 1;
    }
    
    unsigned char fileDigest[64];
    char fileDigestStr[129];
    char diff[129];
    FILE* f = fopen(argv[2], "r");
    if (f == NULL)
    {
        printf("papilio : cmpf : file not found : \"%s\"\n", argv[2]);
        return 1;
    }
    else
    {
        hashFile(fileDigest, hf, f);
        fclose(f);
        bytesToHexa(fileDigestStr, fileDigest, hf->digestSize);
    }
    if (isDigest(argv[3], hf->digestSize))
    {
        printf("%s (%s digest of \"%s\")\n", fileDigestStr, hf->name, argv[2]);
        printf("%s (expected digest)\n", argv[3]);
        if (strcmpdiff(diff, fileDigestStr, argv[3]))
            printf("%s (difference)\nNot equal\n", diff);
        else
            printf("Equal\n");
    }
    else if ( (f = fopen(argv[3], "r")) != NULL)
    {
        hashFile(fileDigest, hf, f);
        fclose(f);
        char fileDigestStr2[129];
        bytesToHexa(fileDigestStr2, fileDigest, hf->digestSize);
        printf("%s (%s digest of \"%s\")\n", fileDigestStr, hf->name, argv[2]);
        printf("%s (%s digest of \"%s\")\n", fileDigestStr2, hf->name, argv[3]);
        if (strcmpdiff(diff, fileDigestStr, fileDigestStr2))
            printf("%s (difference)\nNot equal\n", diff);
        else
            printf("Equal\n");
    }
    else
    {
        printf("papilio : cmpf : \"%s\" is neither a file neither a %s digest\n", argv[3], argv[1]);
        return 1;
    }
    return 0;
}
