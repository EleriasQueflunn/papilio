mkdir obj
cd obj
gcc.exe -c -Wall -Ofast ../src/*.c
cd ..
gcc.exe -Wall -Ofast obj/*.o -o papilio.exe
