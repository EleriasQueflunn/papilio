mkdir obj
cd obj
gcc.exe -c -Wall -Ofast ../src/md2.c ../src/md45.c ../src/sha01.c ../src/sha2.c ../src/sha3.c ../src/hash.c ../src/papilio.c ../src/func.c
cd ..
gcc.exe -Wall -Ofast obj/md2.o obj/md45.o obj/sha01.o obj/sha2.o obj/sha3.o obj/hash.o obj/papilio.o obj/func.o -o papilio.exe
