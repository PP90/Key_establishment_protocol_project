gcc clientSide.c -o client -lcrypto -Wall -Werror
gcc serverSide.c -o server -lcrypto -Wall -Werror
./server
