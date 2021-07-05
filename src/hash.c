/*
--------------hash.c--------------
Author :      Elerias
Date :        05.08.2021
Version :     0.8
Description : Hash function using
----------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "md2.h"
#include "md45.h"
#include "sha01.h"
#include "sha2.h"
#include "sha3.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

static int testkuplets(const char*, int, int, int, HashCrackParameters*);
static int testRepetitionskuplets(const char*, int, int, int, int, HashCrackParameters*);

// Commun passwords whose length > 4 which are not a keyboard sequence (azerty, aqwzsx, 987654231 ...)
const char passwords[100][11] =
{"password",   "dragon",     "baseball",   "football",   "monkey",     "letmein",    "shadow",     "master",     "mustang",    "michael",
 "pussy",      "superman",   "fuckyou",    "killer",     "trustno1",   "jordan",     "jennifer",   "hunter",     "buster",     "soccer",
 "harley",     "batman",     "andrew",     "tigger",     "sunshine",   "iloveyou",   "fuckme",     "charlie",    "robert",     "thomas",
 "hockey",     "ranger",     "daniel",     "starwars",   "klaster",    "george",     "asshole",    "computer",   "michelle",   "jessica",
 "pepper",     "freedom",    "maggie",     "159753",     "ginger",     "princess",   "joshua",     "cheese",     "amanda",     "summer",
 "ashley",     "nicole",     "chelsea",    "biteme",     "matthew",    "access",     "yankees",    "dallas",     "austin",     "thunder",
 "taylor",     "matrix",     "william",    "corvette",   "hello",      "martin",     "heather",    "secret",     "YourNan",    "merlin",
 "diamond",    "hammer",     "silver",     "anthony",    "justin",     "bailey",     "patrick",    "internet",   "scooter",    "golfer",
 "cookie",     "richard",    "samantha",   "bigdog",     "guitar",     "jackson",    "whathever",  "mickey",     "chicken",    "sparky",
 "snoopy",     "maverick",   "phoenix",    "camaro",     "peanut",     "morgan",     "welcome",    "falcon",     "cowboy",     "ferrari"};

const char implementedHashFunctions[15][11] = {"md2", "md4", "md5", "sha0", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256", "sha3_224", "sha3_256", "sha3_384", "sha3_512"};
static MD2Context md2c;
static MD45Context md45c;
static SHA01Context sha01c;
static SHA2x32Context sha2x32c;
static SHA2x64Context sha2x64c;
static SHA3Context sha3c;

int setHashFunction(HashFunction* hf, const char* name)
// Configure HashFunction parameters (name, blockSize ...), return 1 if name is not an implemented hash function else 0.
{
    {
        int a=1;
        for (int k=0 ; k<15 ; k++)
        {
            a = (a && strcmp(name, implementedHashFunctions[k]));
        }
        if (a) return 1;
    }
    
    strcpy(hf->name, name);
    
    if (strcmp(name, "md2") == 0)
    {
        hf->blockSize = 16;
        hf->digestSize = 16;
        hf->context = &md2c;
        hf->hashInit = &MD2Init;
        hf->hashProcessBlock = &MD2ProcessBlock;
        hf->hashProcessLastBlock = &MD2ProcessLastBlock;
        hf->hashGetDigest = &MD2GetDigest;
    }
    else if ( (strcmp(name, "md4") && strcmp(name, "md5")) == 0 )
    {
        hf->blockSize = 64;
        hf->digestSize = 16;
        hf->context = &md45c;

        if (strcmp(name, "md4") == 0)
        {
            hf->hashInit = &MD4Init;
        }
        else
        {
            hf->hashInit = &MD5Init;
        }

        hf->hashProcessBlock = &MD45ProcessBlock;
        hf->hashProcessLastBlock = &MD45ProcessLastBlock;
        hf->hashGetDigest = &MD45GetDigest;
    }
    else if ( (strcmp(name, "sha0") && strcmp(name, "sha1")) == 0 )
    {
        hf->blockSize = 64;
        hf->digestSize = 20;
        hf->context = &sha01c;

        if (strcmp(name, "sha0") == 0)
        {
            hf->hashInit = &SHA0Init;
        }
        else
        {
            hf->hashInit = &SHA1Init;
        }

        hf->hashProcessBlock = &SHA01ProcessBlock;
        hf->hashProcessLastBlock = &SHA01ProcessLastBlock;
        hf->hashGetDigest = &SHA01GetDigest;
    }
    else if ( (strcmp(name, "sha224") && strcmp(name, "sha256")) == 0 )
    {
        hf->blockSize = 64;
        hf->context = &sha2x32c;

        if (strcmp(name, "sha224") == 0)
        {
            hf->digestSize = 28;
            hf->hashInit = &SHA224Init;
        }
        else
        {
            hf->digestSize = 32;
            hf->hashInit = &SHA256Init;
        }

        hf->hashProcessBlock = &SHA2x32ProcessBlock;
        hf->hashProcessLastBlock = &SHA2x32ProcessLastBlock;
        hf->hashGetDigest = &SHA2x32GetDigest;
    }
    else if ( (strcmp(hf->name, "sha384") && strcmp(hf->name, "sha512") && strcmp(hf->name, "sha512_224") && strcmp(hf->name, "sha512_256")) == 0 )
    {
        hf->blockSize = 128;
        hf->context = &sha2x64c;

        if (strcmp(name, "sha384") == 0)
        {
            hf->digestSize = 48;
            hf->hashInit = &SHA384Init;
        }
        else if (strcmp(name, "sha512") == 0)
        {
            hf->digestSize = 64;
            hf->hashInit = &SHA512Init;
        }
        else if (strcmp(name, "sha512_224") == 0)
        {
            hf->digestSize = 28;
            hf->hashInit = &SHA512_224Init;
        }
        else if (strcmp(name, "sha512_256") == 0)
        {
            hf->digestSize = 32;
            hf->hashInit = &SHA512_256Init;
        }

        hf->hashProcessBlock = &SHA2x64ProcessBlock;
        hf->hashProcessLastBlock = &SHA2x64ProcessLastBlock;
        hf->hashGetDigest = &SHA2x64GetDigest;
    }
    else if ( (strcmp(name, "sha3_224") && strcmp(name, "sha3_256") && strcmp(name, "sha3_384") && strcmp(name, "sha3_512") ) == 0 )
    {
        if (strcmp(name, "sha3_224") == 0)
        {
            hf->blockSize = 144;
            hf->digestSize = 28;
            hf->hashInit = &SHA3_224Init;
        }
        else if (strcmp(name, "sha3_256") == 0)
        {
            hf->blockSize = 136;
            hf->digestSize = 32;
            hf->hashInit = &SHA3_256Init;
        }
        else if (strcmp(name, "sha3_384") == 0)
        {
            hf->blockSize = 104;
            hf->digestSize = 48;
            hf->hashInit = &SHA3_384Init;
        }
        else
         {
            hf->blockSize = 72;
            hf->digestSize = 64;
            hf->hashInit = &SHA3_512Init;
        }
        
        hf->context = &sha3c;

        hf->hashProcessBlock = &SHA3ProcessBlock;
        hf->hashProcessLastBlock = &SHA3ProcessLastBlock;
        hf->hashGetDigest = &SHA3GetDigest;
    }
    return 0;
}

void hashText(unsigned char* digest, const HashFunction* hf, const char* msg, unsigned int len)
// Hash a text.
{
    hf->hashInit(hf->context);
    unsigned int i=0;
    while (i + hf->blockSize <= len)
    {
        hf->hashProcessBlock(hf->context, msg+i);
        i += hf->blockSize;
    }
    hf->hashProcessLastBlock(hf->context, msg+i, len-i);
    hf->hashGetDigest(digest, hf->context);
}

void hashFile(unsigned char* digest, const HashFunction* hf, FILE* file)
// Hash a file.
{
    hf->hashInit(hf->context);
    unsigned char buffer[1024];
    unsigned int s = (unsigned int) fread(buffer, 1, hf->blockSize, file);
    while (s == hf->blockSize)
    {
        hf->hashProcessBlock(hf->context, buffer);
        s = (unsigned int) fread(buffer, 1, hf->blockSize, file);
    }
    hf->hashProcessLastBlock(hf->context, buffer, s);
    hf->hashGetDigest(digest, hf->context);
}

#define TRY(P, LEN) \
    { \
        int b; \
        P->hf->hashInit(P->hf->context); \
        P->hf->hashProcessLastBlock(P->hf->context, P->buffer, LEN); \
        P->hf->hashGetDigest(P->digest, P->hf->context); \
        for (int try_j=0 ; try_j<P->nWords ; ++try_j) \
        { \
            if (P->correctPreimages[try_j]) continue; \
            b = 1; \
            for (int k=0 ; k < P->hf->digestSize ; ++k) \
            { \
                b &= (P->digests[try_j][k] == P->digest[k]); \
            } \
            if (b) \
            { \
                for (int k=0 ; k<16 ; ++k) P->preimages[16*try_j+k] = P->buffer[k]; \
                if (LEN != 0) P->correctPreimages[try_j] = LEN; \
                else P->correctPreimages[try_j] = -1; \
                if (++(P->success) == P->nWords) return 1; \
            } \
        } \
    }

#define VPRINTF(S) if (P->verbose) printf(S);

static int testPasswords(HashCrackParameters* P)
{
    for (int i=0 ; i<100 ; i++)
    {
        for (int j=0 ; j<11 ; j++) P->buffer[j] = passwords[i][j];
        TRY(P, strlen(P->buffer))
    }
    return 0;
}

static int testkuplets(const char* alph, int alphLen, int k, int currentLen, HashCrackParameters* P)
{
    if (currentLen < k)
    {
        for (int i=0 ; i<alphLen ; i++)
        {
            P->buffer[currentLen] = alph[i];
            if (currentLen == k - 1)
            {
                TRY(P, k)
            }
            else
            {
                if (testkuplets(alph, alphLen, k, currentLen+1, P)) return 1;
            }
        }
        P->buffer[currentLen] = 0;
    }
    return 0;
}

static int testRepetitionskuplets(const char* alph, int alphLen, int k, int currentLen, int maxRepetitions, HashCrackParameters* P)
{
    if (currentLen < k)
    {
        for (int i=0 ; i<alphLen ; i++)
        {
            P->buffer[currentLen] = alph[i];
            if (currentLen == k - 1)
            {
                for (int j=0 ; j < maxRepetitions ; j++)
                {
                    for (int j2=0 ; j2<k ; j2++) P->buffer[j*k+j2] = P->buffer[j2];
                    TRY(P, (j+1)*k)
                }
                for (int j=k ; j<16 ; j++) P->buffer[j] = 0;
            }
            else
            {
                if (testRepetitionskuplets(alph, alphLen, k, currentLen+1, maxRepetitions, P)) return 1;
            }
        }
        P->buffer[currentLen] = 0;
    }
    return 0;
}

static int testKeyboardSequences(const char* alph, int alphLen, HashCrackParameters* P)
{
    int i, j;
    for (i=0 ; i<alphLen ; i++)
    {
        for (j=0 ; j<16 ; j++) P->buffer[j] = 0;
        for (j=i ; j<MIN(i+16, alphLen) ; j++)
        {
            P->buffer[j-i] = alph[j];
            TRY(P, j-i+1);
        }
        for (j=0 ; j<16 ; j++) P->buffer[j] = 0;
        for (j=i ; j>MAX(i-16, 0) ; j--)
        {
            P->buffer[i-j] = alph[j];
            TRY(P, i-j+1);
        }
    }
    return 0;
}

int hashCrackBruteForce(HashCrackParameters* P)
// Try preimage attacks by brute force.
{
    for (int k=0 ; k<16 ; k++) P->buffer[k]=0;

    VPRINTF("Starting preimage attacks ...\n");
    
    VPRINTF("Level 0 (< 1 s) \n")
    
    VPRINTF("1. Null string (1)\n")
    TRY(P, 0)

    VPRINTF("2. Common passwords (100)\n")
    if (testPasswords(P)) return 1;
    for (int k=0 ; k<16 ; k++) P->buffer[k]=0;
    
    char alph_all[256];
    for (int i=0 ; i<256 ; ++i)
        alph_all[i]=i;
    char alph_min[27] = "abcdefghijklmnopqrstuvwxyz";
    char alph_maj[27] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char alph_fig[11] = "0123456789";
    char alph_alpha[63] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char alph_ascii[95];
    for (int i=32 ; i<127 ; ++i)
        alph_ascii[i-32] = i;

    VPRINTF("3. Repetitions of one character (4 096)\n")
    if (testRepetitionskuplets(alph_all, 256, 1, 0, 16, P)) return 1;
    
    VPRINTF("4. Keyboard sequences\n")
    const char* AKS[] =
    {"azertyuiopqsdfghjklmwxcvbn", "qwertyuiopasdfghjklzxcvbnm", "abcdefghijklmnopqrstuvwxyz", "AZERTYUIOPQSDFGHJKLMWXCVBN", "QWERTYUIOPASDFGHJKLZXCVBNM",
     "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "²&é\"'(-è_çà)=",             "~1234567890°+",              "~!@#$%^&*()_+",              "`1234567890-=",
     "azertyuiop^$",               "qsdfghjklmù*",               "<wxcvbn,;:!",                "QSDFGHJKLM%µ",               ">WXCVBN?./§\"}",
     "&aqwézsx\"edc'rfv(tgb-yhnèuj,_ik;çol:àpm!",                "&aqwxszé\"edcvfr'(tgbnhy-èuj,;ki_çol:!mpà",
     "aqwzsxedcrfvtgbyhnuj,ik;ol:pm!",                           "aqwxszedcvfrtgbnhyuj,;kiol:!mp",
     "1AQW2ZSX3EDC4RFV5TGB6YHN7UJ?8IK.9OL/0PM§",                 "1AQWXSZ23EDCVFR45TGBNHY67UJ?.KI89OL/§MP0",
     "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/",                 "1qazxsw23edcvfr45tgbnhy67ujm,ki89ol./;p0",
     "!QAZ@WSX#EDC$RFV%TGB^YHN&UJM*IK<(OL>)P:?",                 "!QAZXSW@#EDCVFR$%TGBNHY^&UJM<KI*(OL>?:P)"};

    for (int k=0 ; k<23 ; k++)
    {
        if (testKeyboardSequences(AKS[k], strlen(AKS[k]), P)) return 1;
    }
    
    VPRINTF("5. Two characters (65 536)\n")
    if (testkuplets(alph_all, 256, 2, 0, P)) return 1;
    
    VPRINTF("6. Repetitions of three figures (5 000)\n")
    if (testRepetitionskuplets(alph_fig, 10, 3, 0, 5, P)) return 1;
    
    VPRINTF("7. Repetitions of four figures (40 000)\n")
    if (testRepetitionskuplets(alph_fig, 10, 4, 0, 4, P)) return 1;
    
    VPRINTF("8. Repetitions of three minuscules (87 880)\n")
    if (testRepetitionskuplets(alph_min, 26, 3, 0, 5, P)) return 1;
    
    VPRINTF("9. Repetitions of three majuscules (87 880)\n")
    if (testRepetitionskuplets(alph_maj, 26, 3, 0, 5, P)) return 1;
    
    VPRINTF("10. Repetitions of two ascii printable characters (72 200)\n")
    if (testRepetitionskuplets(alph_ascii, 95, 2, 0, 8, P)) return 1;
    
    if (P->level == 0) return 0;
    
    VPRINTF("Level 1 (< 10 s) \n")
    
    VPRINTF("11. Repetitions of two characters (524 288)\n")
    if (testRepetitionskuplets(alph_all, 256, 2, 0, 8, P)) return 1;
    
    VPRINTF("12. Repetitions of five figures (300 000)\n")
    if (testRepetitionskuplets(alph_fig, 10, 5, 0, 3, P)) return 1;
    
    VPRINTF("13. Four minuscules (456 976)\n")
    if (testkuplets(alph_min, 26, 4, 0, P)) return 1;
    
    VPRINTF("14. Four majuscules (456 976)\n")
    if (testkuplets(alph_maj, 26, 4, 0, P)) return 1;
    
    VPRINTF("15. Six figures (1 000 000)\n")
    if (testkuplets(alph_fig, 10, 6, 0, P)) return 1;
    
    VPRINTF("16. Repetitions of three alpha-numeric characters (1 191 640)\n")
    if (testRepetitionskuplets(alph_alpha, 62, 3, 0, 5, P)) return 1;
    
    VPRINTF("17. Three ascii printable characters (857 375)\n")
    if (testkuplets(alph_ascii, 95, 3, 0, P)) return 1;
    
    if (P->level == 1) return 0;
    
    VPRINTF("Level 2 (< 100 s) \n")
    
    VPRINTF("18. Repetitions of six figures (2 000 000)\n")
    if (testRepetitionskuplets(alph_fig, 10, 6, 0, 2, P)) return 1;
    
    VPRINTF("19. Repetitions of four minuscules (1 827 904)\n")
    if (testRepetitionskuplets(alph_min, 26, 4, 0, 4, P)) return 1;
    
    VPRINTF("20. Repetitions of four majuscules (1 827 904)\n")
    if (testRepetitionskuplets(alph_maj, 26, 4, 0, 4, P)) return 1;
    
    VPRINTF("21. Repetitions of three ascii printable characters (4 286 875)\n")
    if (testRepetitionskuplets(alph_ascii, 95, 3, 0, 5, P)) return 1;
    
    VPRINTF("22. Three characters (16 777 216)\n")
    if (testkuplets(alph_all, 256, 3, 0, P)) return 1;
    
    VPRINTF("23. Four alpha-numeric characters (14 776 336)\n")
    if (testkuplets(alph_alpha, 62, 4, 0, P)) return 1;
    
    if (P->level == 2) return 0;
    
    VPRINTF("Level 3 (< 1 000 s) \n")
    
    VPRINTF("24. Repetitions of seven figures (20 000 000)\n")
    if (testRepetitionskuplets(alph_fig, 10, 7, 0, 2, P)) return 1;
    
    VPRINTF("25. Repetitions of five minuscules (35 644 128)\n")
    if (testRepetitionskuplets(alph_min, 26, 5, 0, 3, P)) return 1;
    
    VPRINTF("26. Repetitions of five majuscules (35 644 128)\n")
    if (testRepetitionskuplets(alph_maj, 26, 5, 0, 3, P)) return 1;
    
    VPRINTF("27. Four ascii printable characters (81 450 625)\n")
    if (testkuplets(alph_ascii, 95, 4, 0, P)) return 1;
    
    VPRINTF("28. Repetitions of three characters (83 886 080)\n")
    if (testRepetitionskuplets(alph_all, 256, 3, 0, 5, P)) return 1;
    
    VPRINTF("29. Repetitions of four alpha-numeric characters (59 105 344)\n")
    if (testRepetitionskuplets(alph_alpha, 62, 4, 0, 4, P)) return 1;
    
    if (P->level == 3) return 0;
    
    VPRINTF("Level 4 (< 10 000 s) \n")
    
    VPRINTF("30. Repetitions of eight figures (200 000 000)\n")
    if (testRepetitionskuplets(alph_fig, 10, 8, 0, 2, P)) return 1;
    
    VPRINTF("31. Nine figures (1 000 000 000)\n")
    if (testkuplets(alph_fig, 10, 9, 0, P)) return 1;
    
    VPRINTF("32. Repetitions of six minuscules (617 831 552)\n")
    if (testRepetitionskuplets(alph_min, 26, 6, 0, 2, P)) return 1;
    
    VPRINTF("33. Repetitions of six majuscules (617 831 552)\n")
    if (testRepetitionskuplets(alph_maj, 26, 6, 0, 2, P)) return 1;
    
    VPRINTF("34. Repetitions of four ascii printable characters (325 802 500)\n")
    if (testRepetitionskuplets(alph_ascii, 95, 4, 0, 4, P)) return 1;
    
    VPRINTF("35. Five alpha-numeric characters (916 132 832)\n")
    if (testkuplets(alph_alpha, 62, 5, 0, P)) return 1;
    
    if (P->level == 4) return 0;
    
    VPRINTF("Level 5 (< 100 000 s) \n")
    
    VPRINTF("36. Ten figures (10 000 000 000)\n")
    if (testkuplets(alph_fig, 10, 10, 0, P)) return 1;
    
    VPRINTF("37. Seven minuscules (8 031 810 176)\n")
    if (testkuplets(alph_min, 26, 7, 0, P)) return 1;
    
    VPRINTF("38. Seven majuscules (8 031 810 176)\n")
    if (testkuplets(alph_maj, 26, 7, 0, P)) return 1;
    
    VPRINTF("39. Four characters (4 294 967 296)\n")
    if (testkuplets(alph_all, 256, 4, 0, P)) return 1;
    
    VPRINTF("40. Five ascii printable characters (7 737 809 375)\n")
    if (testkuplets(alph_ascii, 95, 5, 0, P)) return 1;
    
    VPRINTF("41. Repetitions of five alpha-numeric characters (2 748 398 496)\n")
    if (testRepetitionskuplets(alph_alpha, 62, 5, 0, 3, P)) return 1;

    return 0;
} 