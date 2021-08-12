/*
--------------hash.c--------------
Author :      Elerias
Date :        12.08.2021
Version :     0.12
Description : Hash function using
----------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "func.h"
#include "md2.h"
#include "md45.h"
#include "sha01.h"
#include "sha2.h"
#include "sha3.h"
#include "adler32.h"
#include "crc.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

static int testkuplets(const char*, int, int, int, HashCrackParameters*);
static int testRepetitionskuplets(const char*, int, int, int, int, HashCrackParameters*);

// Top 1000 passwords
const char* passwords[1000] =
{"123456",      "password",    "12345678",    "qwerty",      "123456789",   "12345",       "1234",        "111111",      "1234567",     "dragon",
 "123123",      "baseball",    "abc123",      "football",    "monkey",      "letmein",     "696969",      "shadow",      "master",      "666666",
 "qwertyuiop",  "123321",      "mustang",     "1234567890",  "michael",     "654321",      "pussy",       "superman",    "1qaz2wsx",    "7777777",
 "fuckyou",     "121212",      "000000",      "qazwsx",      "123qwe",      "killer",      "trustno1",    "jordan",      "jennifer",    "zxcvbnm",
 "asdfgh",      "hunter",      "buster",      "soccer",      "harley",      "batman",      "andrew",      "tigger",      "sunshine",    "iloveyou",
 "fuckme",      "2000",        "charlie",     "robert",      "thomas",      "hockey",      "ranger",      "daniel",      "starwars",    "klaster",
 "112233",      "george",      "asshole",     "computer",    "michelle",    "jessica",     "pepper",      "1111",        "zxcvbn",      "555555",
 "11111111",    "131313",      "freedom",     "777777",      "pass",        "fuck",        "maggie",      "159753",      "aaaaaa",      "ginger",
 "princess",    "joshua",      "cheese",      "amanda",      "summer",      "love",        "ashley",      "6969",        "nicole",      "chelsea",
 "biteme",      "matthew",     "access",      "yankees",     "987654321",   "dallas",      "austin",      "thunder",     "taylor",      "matrix",
 "william",     "corvette",    "hello",       "martin",      "heather",     "secret",      "YourNan",     "merlin",      "diamond",     "1234qwer",
 "gfhjkm",      "hammer",      "silver",      "222222",      "88888888",    "anthony",     "justin",      "test",        "bailey",      "q1w2e3r4t5",
 "patrick",     "internet",    "scooter",     "orange",      "11111",       "golfer",      "cookie",      "richard",     "samantha",    "bigdog",
 "guitar",      "jackson",     "whatever",    "mickey",      "chicken",     "sparky",      "snoopy",      "maverick",    "phoenix",     "camaro",
 "sexy",        "peanut",      "morgan",      "welcome",     "falcon",      "cowboy",      "ferrari",     "samsung",     "andrea",      "smokey",
 "steelers",    "joseph",      "mercedes",    "dakota",      "arsenal",     "eagles",      "melissa",     "boomer",      "booboo",      "spider",
 "nascar",      "monster",     "tigers",      "yellow",      "xxxxxx",      "123123123",   "gateway",     "marina",      "diablo",      "bulldog",
 "qwer1234",    "compaq",      "purple",      "hardcore",    "banana",      "junior",      "hannah",      "123654",      "porsche",     "lakers",
 "iceman",      "money",       "cowboys",     "987654",      "london",      "tennis",      "999999",      "ncc1701",     "coffee",      "scooby",
 "0000",        "miller",      "boston",      "q1w2e3r4",    "fuckoff",     "brandon",     "yamaha",      "chester",     "mother",      "forever",
 "johnny",      "edward",      "333333",      "oliver",      "redsox",      "player",      "nikita",      "knight",      "fender",      "barney",
 "midnight",    "please",      "brandy",      "chicago",     "badboy",      "iwantu",      "slayer",      "rangers",     "charles",     "angel",
 "flower",      "bigdaddy",    "rabbit",      "wizard",      "bigdick",     "jasper",      "enter",       "rachel",      "chris",       "steven",
 "winner",      "adidas",      "victoria",    "natasha",     "1q2w3e4r",    "jasmine",     "winter",      "prince",      "panties",     "marine",
 "ghbdtn",      "fishing",     "cocacola",    "casper",      "james",       "232323",      "raiders",     "888888",      "marlboro",    "gandalf",
 "asdfasdf",    "crystal",     "87654321",    "12344321",    "sexsex",      "golden",      "blowme",      "bigtits",     "8675309",     "panther",
 "lauren",      "angela",      "bitch",       "spanky",      "thx1138",     "angels",      "madison",     "winston",     "shannon",     "mike",
 "toyota",      "blowjob",     "jordan23",    "canada",      "sophie",      "Password",    "apples",      "dick",        "tiger",       "razz",
 "123abc",      "pokemon",     "qazxsw",      "55555",       "qwaszx",      "muffin",      "johnson",     "murphy",      "cooper",      "jonathan",
 "liverpoo",    "david",       "danielle",    "159357",      "jackie",      "1990",        "123456a",     "789456",      "turtle",      "horny",
 "abcd1234",    "scorpion",    "qazwsxedc",   "101010",      "butter",      "carlos",      "password1",   "dennis",      "slipknot",    "qwerty123",
 "booger",      "asdf",        "1991",        "black",       "startrek",    "12341234",    "cameron",     "newyork",     "rainbow",     "nathan",
 "john",        "1992",        "rocket",      "viking",      "redskins",    "butthead",    "asdfghjkl",   "1212",        "sierra",      "peaches",
 "gemini",      "doctor",      "wilson",      "sandra",      "helpme",      "qwertyui",    "victor",      "florida",     "dolphin",     "pookie",
 "captain",     "tucker",      "blue",        "liverpool",   "theman",      "bandit",      "dolphins",    "maddog",      "packers",     "jaguar",
 "lovers",      "nicholas",    "united",      "tiffany",     "maxwell",     "zzzzzz",      "nirvana",     "jeremy",      "suckit",      "stupid",
 "porn",        "monica",      "elephant",    "giants",      "jackass",     "hotdog",      "rosebud",     "success",     "debbie",      "mountain",
 "444444",      "xxxxxxxx",    "warrior",     "1q2w3e4r5t",  "q1w2e3",      "123456q",     "albert",      "metallic",    "lucky",       "azerty",
 "7777",        "shithead",    "alex",        "bond007",     "alexis",      "1111111",     "samson",      "5150",        "willie",      "scorpio",
 "bonnie",      "gators",      "benjamin",    "voodoo",      "driver",      "dexter",      "2112",        "jason",       "calvin",      "freddy",
 "212121",      "creative",    "12345a",      "sydney",      "rush2112",    "1989",        "asdfghjk",    "red123",      "bubba",       "4815162342",
 "passw0rd",    "trouble",     "gunner",      "happy",       "fucking",     "gordon",      "legend",      "jessie",      "stella",      "qwert",
 "eminem",      "arthur",      "apple",       "nissan",      "bullshit",    "bear",        "america",     "1qazxsw2",    "nothing",     "parker",
 "4444",        "rebecca",     "qweqwe",      "garfield",    "01012011",    "beavis",      "69696969",    "jack",        "asdasd",      "december",
 "2222",        "102030",      "252525",      "11223344",    "magic",       "apollo",      "skippy",      "315475",      "girls",       "kitten",
 "golf",        "copper",      "braves",      "shelby",      "godzilla",    "beaver",      "fred",        "tomcat",      "august",      "buddy",
 "airborne",    "1993",        "1988",        "lifehack",    "qqqqqq",      "brooklyn",    "animal",      "platinum",    "phantom",     "online",
 "xavier",      "darkness",    "blink182",    "power",       "fish",        "green",       "789456123",   "voyager",     "police",      "travis",
 "12qwaszx",    "heaven",      "snowball",    "lover",       "abcdef",      "00000",       "pakistan",    "007007",      "walter",      "playboy",
 "blazer",      "cricket",     "sniper",      "hooters",     "donkey",      "willow",      "loveme",      "saturn",      "therock",     "redwings",
 "bigboy",      "pumpkin",     "trinity",     "williams",    "tits",        "nintendo",    "digital",     "destiny",     "topgun",      "runner",
 "marvin",      "guinness",    "chance",      "bubbles",     "testing",     "fire",        "november",    "minecraft",   "asdf1234",    "lasvegas",
 "sergey",      "broncos",     "cartman",     "private",     "celtic",      "birdie",      "little",      "cassie",      "babygirl",    "donald",
 "beatles",     "1313",        "dickhead",    "family",      "12121212",    "school",      "louise",      "gabriel",     "eclipse",     "fluffy",
 "147258369",   "lol123",      "explorer",    "beer",        "nelson",      "flyers",      "spencer",     "scott",       "lovely",      "gibson",
 "doggie",      "cherry",      "andrey",      "snickers",    "buffalo",     "pantera",     "metallica",   "member",      "carter",      "qwertyu",
 "peter",       "alexande",    "steve",       "bronco",      "paradise",    "goober",      "5555",        "samuel",      "montana",     "mexico",
 "dreams",      "michigan",    "cock",        "carolina",    "yankee",      "friends",     "magnum",      "surfer",      "poopoo",      "maximus",
 "genius",      "cool",        "vampire",     "lacrosse",    "asd123",      "aaaa",        "christin",    "kimberly",    "speedy",      "sharon",
 "carmen",      "111222",      "kristina",    "sammy",       "racing",      "ou812",       "sabrina",     "horses",      "0987654321",  "qwerty1",
 "pimpin",      "baby",        "stalker",     "enigma",      "147147",      "star",        "poohbear",    "boobies",     "147258",      "simple",
 "bollocks",    "12345q",      "marcus",      "brian",       "1987",        "qweasdzxc",   "drowssap",    "hahaha",      "caroline",    "barbara",
 "dave",        "viper",       "drummer",     "action",      "einstein",    "bitches",     "genesis",     "hello1",      "scotty",      "friend",
 "forest",      "010203",      "hotrod",      "google",      "vanessa",     "spitfire",    "badger",      "maryjane",    "friday",      "alaska",
 "1232323q",    "tester",      "jester",      "jake",        "champion",    "billy",       "147852",      "rock",        "hawaii",      "badass",
 "chevy",       "420420",      "walker",      "stephen",     "eagle1",      "bill",        "1986",        "october",     "gregory",     "svetlana",
 "pamela",      "1984",        "music",       "shorty",      "westside",    "stanley",     "diesel",      "courtney",    "242424",      "kevin",
 "porno",       "hitman",      "boobs",       "mark",        "12345qwert",  "reddog",      "frank",       "qwe123",      "popcorn",     "patricia",
 "aaaaaaaa",    "1969",        "teresa",      "mozart",      "buddha",      "anderson",    "paul",        "melanie",     "abcdefg",     "security",
 "lucky1",      "lizard",      "denise",      "3333",        "a12345",      "123789",      "ruslan",      "stargate",    "simpsons",    "scarface",
 "eagle",       "123456789a",  "thumper",     "olivia",      "naruto",      "1234554321",  "general",     "cherokee",    "a123456",     "vincent",
 "Usuckballz1", "spooky",      "qweasd",      "cumshot",     "free",        "frankie",     "douglas",     "death",       "1980",        "loveyou",
 "kitty",       "kelly",       "veronica",    "suzuki",      "semperfi",    "penguin",     "mercury",     "liberty",     "spirit",      "scotland",
 "natalie",     "marley",      "vikings",     "system",      "sucker",      "king",        "allison",     "marshall",    "1979",        "098765",
 "qwerty12",    "hummer",      "adrian",      "1985",        "vfhbyf",      "sandman",     "rocky",       "leslie",      "antonio",     "98765432",
 "4321",        "softball",    "passion",     "mnbvcxz",     "bastard",     "passport",    "horney",      "rascal",      "howard",      "franklin",
 "bigred",      "assman",      "alexander",   "homer",       "redrum",      "jupiter",     "claudia",     "55555555",    "141414",      "zaq12wsx",
 "shit",        "patches",     "nigger",      "cunt",        "raider",      "infinity",    "andre",       "54321",       "galore",      "college",
 "russia",      "kawasaki",    "bishop",      "77777777",    "vladimir",    "money1",      "freeuser",    "wildcats",    "francis",     "disney",
 "budlight",    "brittany",    "1994",        "00000000",    "sweet",       "oksana",      "honda",       "domino",      "bulldogs",    "brutus",
 "swordfis",    "norman",      "monday",      "jimmy",       "ironman",     "ford",        "fantasy",     "9999",        "7654321",     "PASSWORD",
 "hentai",      "duncan",      "cougar",      "1977",        "jeffrey",     "house",       "dancer",      "brooke",      "timothy",     "super",
 "marines",     "justice",     "digger",      "connor",      "patriots",    "karina",      "202020",      "molly",       "everton",     "tinker",
 "alicia",      "rasdzv3",     "poop",        "pearljam",    "stinky",      "naughty",     "colorado",    "123123a",     "water",       "test123",
 "ncc1701d",    "motorola",    "ireland",     "asdfg",       "slut",        "matt",        "houston",     "boogie",      "zombie",      "accord",
 "vision",      "bradley",     "reggie",      "kermit",      "froggy",      "ducati",      "avalon",      "6666",        "9379992",     "sarah",
 "saints",      "logitech",    "chopper",     "852456",      "simpson",     "madonna",     "juventus",    "claire",      "159951",      "zachary",
 "yfnfif",      "wolverin",    "warcraft",    "hello123",    "extreme",     "penis",       "peekaboo",    "fireman",     "eugene",      "brenda",
 "123654789",   "russell",     "panthers",    "georgia",     "smith",       "skyline",     "jesus",       "elizabet",    "spiderma",    "smooth",
 "pirate",      "empire",      "bullet",      "8888",        "virginia",    "valentin",    "psycho",      "predator",    "arizona",     "134679",
 "mitchell",    "alyssa",      "vegeta",      "titanic",     "christ",      "goblue",      "fylhtq",      "wolf",        "mmmmmm",      "kirill",
 "indian",      "hiphop",      "baxter",      "awesome",     "people",      "danger",      "roland",      "mookie",      "741852963",   "1111111111",
 "dreamer",     "bambam",      "arnold",      "1981",        "skipper",     "serega",      "rolltide",    "elvis",       "changeme",    "simon",
 "1q2w3e",      "lovelove",    "fktrcfylh",   "denver",      "tommy",       "mine",        "loverboy",    "hobbes",      "happy1",      "alison",
 "nemesis",     "chevelle",    "cardinal",    "burton",      "wanker",      "picard",      "151515",      "tweety",      "michael1",    "147852369",
 "12312",       "xxxx",        "windows",     "turkey",      "456789",      "1974",        "vfrcbv",      "sublime",     "1975",        "galina",
 "bobby",       "newport",     "manutd",      "daddy",       "american",    "alexandr",    "1966",        "victory",     "rooster",     "qqq111",
 "madmax",      "electric",    "bigcock",     "a1b2c3",      "wolfpack",    "spring",      "phpbb",       "lalala",      "suckme",      "spiderman",
 "eric",        "darkside",    "classic",     "raptor",      "123456789q",  "hendrix",     "1982",        "wombat",      "avatar",      "alpha",
 "zxc123",      "crazy",       "hard",        "england",     "brazil",      "1978",        "01011980",    "wildcat",     "polina",      "freepass"};

#define N_IMP_HASH_FUNCTIONS 19
const char* implementedHashFunctions[N_IMP_HASH_FUNCTIONS] = {"md2", "md4", "md5", "sha0", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "adler32", "crc32", "crc64-iso", "crc64-ecma"};
static MD2Context md2c;
static MD45Context md45c;
static SHA01Context sha01c;
static SHA2x32Context sha2x32c;
static SHA2x64Context sha2x64c;
static SHA3Context sha3c;
static ADLER32Context adler32c;
static CRC32Context crc32c;
static CRC64Context crc64c;

int setHashFunction(HashFunction* hf, const char* name)
// Configure HashFunction parameters (name, blockSize ...), return 1 if name is not an implemented hash function else 0.
{
    {
        int a=1;
        for (int k=0 ; k<N_IMP_HASH_FUNCTIONS ; ++k)
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
    else if (strcmp(name, "adler32") == 0)
    {
        hf->blockSize = 0; // Because adler32 can process n-byte blocks
        hf->digestSize = 4;
        hf->context = &adler32c;
        hf->hashInit = &ADLER32Init;
        hf->hashProcessBlock = &ADLER32Process;
        hf->hashProcessLastBlock = NULL;
        hf->hashGetDigest = &ADLER32GetChecksum;
    }
    else if (strcmp(name, "crc32") == 0)
    {
        hf->blockSize = 0; // Because crc32 can process n-byte blocks
        hf->digestSize = 4;
        hf->context = &crc32c;
        hf->hashInit = &CRC32Init;
        hf->hashProcessBlock = &CRC32Process;
        hf->hashProcessLastBlock = NULL;
        hf->hashGetDigest = &CRC32GetChecksum;
    }
    else if (strcmp(name, "crc64-ecma") == 0)
    {
        hf->blockSize = 0; // Because crc64-ecma can process n-byte blocks
        hf->digestSize = 8;
        hf->context = &crc64c;
        hf->hashInit = &CRC64EInit;
        hf->hashProcessBlock = &CRC64EProcess;
        hf->hashProcessLastBlock = NULL;
        hf->hashGetDigest = &CRC64EGetChecksum;
    }
    else if (strcmp(name, "crc64-iso") == 0)
    {
        hf->blockSize = 0; // Because crc64-iso can process n-byte blocks
        hf->digestSize = 8;
        hf->context = &crc64c;
        hf->hashInit = &CRC64IInit;
        hf->hashProcessBlock = &CRC64IProcess;
        hf->hashProcessLastBlock = NULL;
        hf->hashGetDigest = &CRC64IGetChecksum;
    }

    return 0;
}

void hashText(unsigned char* digest, const HashFunction* hf, const char* msg, unsigned int len)
// Hash a text.
{
    hf->hashInit(hf->context);
    
    if (hf->blockSize)
    {
        unsigned int i=0;
        while (i + hf->blockSize <= len)
        {
            hf->hashProcessBlock(hf->context, msg+i);
            i += hf->blockSize;
        }
        hf->hashProcessLastBlock(hf->context, msg+i, len-i);
    }
    else
    {
        hf->hashProcessBlock(hf->context, msg, len);
    }
    
    hf->hashGetDigest(digest, hf->context);
}

void hashFile(unsigned char* digest, const HashFunction* hf, FILE* file)
// Hash a file.
{
    hf->hashInit(hf->context);
    unsigned char buffer[1024];
    
    if (hf->blockSize)
    {
        unsigned int s = (unsigned int) fread(buffer, 1, hf->blockSize, file);
        while (s == hf->blockSize)
        {
            hf->hashProcessBlock(hf->context, buffer);
            s = (unsigned int) fread(buffer, 1, hf->blockSize, file);
        }
        hf->hashProcessLastBlock(hf->context, buffer, s);
    }
    else
    {
        unsigned int s;
        while ( (s = (unsigned int) fread(buffer, 1, 1024, file)) )
            hf->hashProcessBlock(hf->context, buffer, s);
    }
    
    hf->hashGetDigest(digest, hf->context);
}

#define TRY(P, LEN) \
    { \
        int b; \
        P->hf->hashInit(P->hf->context); \
        if (P->hf->blockSize) \
            P->hf->hashProcessLastBlock(P->hf->context, P->buffer, LEN); \
        else \
            P->hf->hashProcessBlock(P->hf->context, P->buffer, LEN); \
        P->hf->hashGetDigest(P->digest, P->hf->context); \
        for (int try_j=0 ; try_j<P->nWords ; ++try_j) \
        { \
            if (P->correctPreimages[try_j]) \
                continue; \
            b = 1; \
            for (int k=0 ; k < P->hf->digestSize ; ++k) \
                b &= (P->digests[try_j][k] == P->digest[k]); \
            if (b) \
            { \
                for (int k=0 ; k<16 ; ++k) \
                    P->preimages[16*try_j+k] = P->buffer[k]; \
                if (LEN != 0) \
                    P->correctPreimages[try_j] = LEN; \
                else \
                    P->correctPreimages[try_j] = -1; \
                if (++(P->success) == P->nWords) \
                    return 1; \
                else if (P->verbose) \
                { \
                    printf("Preimage of "); \
                    printBytesInHexa(P->digest, P->hf->digestSize); \
                    printf(" :\nHexa : "); \
                    for (int k2=0 ; k2 < LEN ; k2++)  \
                        printf("%02x", P->buffer[k2]); \
                    printf("\nAscii : "); \
                    printf("%s\n", P->buffer); \
                } \
            } \
        } \
    }

#define VPRINTF(S) if (P->verbose) printf(S);

static int testPasswords(HashCrackParameters* P)
{
    for (int i=0 ; i<1000 ; i++)
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
            if (P->verbose && !currentLen)
            {
                printf("%i/%i\r", i, alphLen);
                fflush(stdout);
            }
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
            if (P->verbose && !currentLen)
            {
                printf("%i/%i\r", i, alphLen);
                fflush(stdout);
            }
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

    VPRINTF("Starting preimage attacks ...\n")
    
    VPRINTF("Type Ctrl+c at any time to stop\n")
    
    VPRINTF("1. Null string (1)\n")
    TRY(P, 0)

    VPRINTF("2. Common passwords (1000)\n")
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
    const char* AKS[61] =
    {"abcdefghijklmnopqrstuvwxyz",                "ABCDEFGHIJKLMNOPQRSTUVWXYZ",                "azertyuiopqsdfghjklmwxcvbn",                "AZERTYUIOPQSDFGHJKLMWXCVBN",
     "azertyuiopmlkjhgfdsqwxcvbn",                "AZERTYUIOPMLKJHGFDSQWXCVBN",                "poiuytrezamlkjhgfdsqnbvcxw",                "POIUYTREZAMLKJHGFDSQNBVCXW",
     "qwertyuiopasdfghjklzxcvbnm",                "QWERTYUIOPASDFGHJKLZXCVBNM",                "qwertyuioplkjhgfdsazxcvbnm",                "QWERTYUIOPLKJHGFDSAZXCVBNM",
     "poiuytrewqlkjhgfdsamnbvcxz",                "POIUYTREWQLKJHGFDSAMNBVCXZ",                "²&é\"'(-è_çà)=",                            "~1234567890°+", 
     "~!@#$%^&*()_+",                             "`1234567890-=",                             "azertyuiop^$",                              "qsdfghjklmù*",
     "<wxcvbn,;:!",                               "QSDFGHJKLM%µ",                              ">WXCVBN?./§\"}",                            "qwertyuiop[]",
     "QWERTYUIOP{}",                              "asdfghjkl;'\\",                             "ASDFGHJKL:\"|",                             "<zxcvbnm,./",
     ">ZXCVBNM<>?",
     "&aqwézsx\"edc'rfv(tgb-yhnèuj,_ik;çol:àpm!", "wqa&xszécde\"vfr'bgt(nhy-,juè;ki_:loç!mpà", "&aqwxszé\"edcvfr'(tgbnhy-èuj,;ki_çol:!mpà", "wqa&ézsxcde\"'rfvbgt(-yhn,juè_ik;:loçàpm!",
     "aqwzsxedcrfvtgbyhnuj,ik;ol:pm!",            "wqaxszcdevfrbgtnhy,ju;ki:lo!mp",            "aqwxszedcvfrtgbnhyuj,;kiol:!mp",            "wqazsxcderfvbgtyhn,juik;:lopm!",
     "1AQW2ZSX3EDC4RFV5TGB6YHN7UJ?8IK.9OL/0PM§",  "WQA1XSZ2CDE3VFR4BGT5NHY6?JU7.KI8/LO9§MP0",  "1AQWXSZ23EDCVFR45TGBNHY67UJ?.KI89OL/§MP0",  "WQA12ZSXCDE34RFVBGT56YHN?JU78IK./LO90PM§",
     "AQWZSXEDCRFVTGBYHNUJ?IK.OL/PM§",            "WQAXSZCDEVFRBGTNHY?JU.KI/LO§MP",            "AQWXSZEDCVFRTGBNHYUJ?.KIOL/§MP",            "WQAZSXCDERFVBGTYHN?JUIK./LOPM§",
     "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/",  "zaq1xsw2cde3vfr4bgt5nhy6mju7,ki8.lo9/;p0",  "1qazxsw23edcvfr45tgbnhy67ujm,ki89ol./;p0",  "zaq12wsxcde34rfvbgt56yhnmju78ik,.lo90p;/",
     "qazwsxedcrfvtgbyhnujmik,ol.p;/",            "zaqxswcdevfrbgtnhymju,ki.lo/;p",            "qazxswedcvfrtgbnhyujm,kiol./;p",            "zaqwsxcderfvbgtyhnmjuik,.lop;/",
     "!QAZ@WSX#EDC$RFV%TGB^YHN&UJM*IK<(OL>)P:?",  "ZAQ!XSW@CDE#VFR$BGT%NHY^MJU&<KI*>LO(?:P)",  "!QAZXSW@#EDCVFR$%TGBNHY^&UJM<KI*(OL>?:P)",  "ZAQ!@WSXCDE#$RFVBGT%^YHNMJU&*IK<>LO()P:?",
     "QAZWSXEDCRFVTGBYHNUJMIK<OL>P:?",            "ZAQXSWCDEVFRBGTNHYMJU<KI>LO?:P",            "QAZXSWEDCVFRTGBNHYUJM<KIOL>?:P",            "ZAQWSXCDERFVBGTYHNMJUIK<>LOP:?"};

    for (int k=0 ; k<61 ; k++)
    {
        if (testKeyboardSequences(AKS[k], strlen(AKS[k]), P)) return 1;
    }
    
    int count[12] = {2,  2,        2,     2,         2,            2,            2,   2,       2,   2,       2,       2};
    /*             char, rep_char, pchar, rep_pchar, rep_alphanum, rep_alphanum, min, rep_min, maj, rep_maj, digits, rep_digits*/
    int lengths[12] = {256, 256, 95, 95, 62, 62, 26, 26, 26, 26, 10, 10};
    char* alphs[12] = {alph_all, alph_all, alph_ascii, alph_ascii, alph_alpha, alph_alpha, alph_min, alph_min, alph_maj, alph_maj, alph_fig, alph_fig};
    char* types[12] = {"characters", "characters", "ascii printable characters", "ascii printable characters", "alphanumeric characters", "alphanumeric characters", "lowercases", "lowercases", "uppercases" , "uppercases", "digits", "digits"};
    
    unsigned long int mini;
    int index_mini=0;
    unsigned long int n;
    int step=5;
    int end=0;
    
    while (!end)
    {
        mini = -1;
        for (int k=0 ; k<12 ; ++k)
        {
            if (k % 2)
                n = 1;
            else
                n = 16 / count[k];
            for (int i=0 ; i<count[k] ; ++i) n *= lengths[k];
            if (n < mini)
            {
                mini = n;
                index_mini = k;
            }
        }
        
        if (index_mini % 2)
        {
            if (P->verbose) printf("%i. %i %s (%li)\n", step, count[index_mini], types[index_mini], mini);
            end = testkuplets(alphs[index_mini], lengths[index_mini], count[index_mini], 0, P);
        }
        else
        {
            if (P->verbose) printf("%i. Repetitions of %i %s (%li)\n", step, count[index_mini], types[index_mini], mini);
            end = testRepetitionskuplets(alphs[index_mini], lengths[index_mini], count[index_mini], 0, 16 / count[index_mini], P);
        }
        ++count[index_mini];
        ++step;
    }
    
    return 1;
} 
