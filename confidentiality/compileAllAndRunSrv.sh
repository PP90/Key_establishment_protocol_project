gcc clientSide.c -o client -lcrypto 
gcc serverSide.c -o server -lcrypto 
./server
