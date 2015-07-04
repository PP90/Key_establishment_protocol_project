#Make file of SCNS project.


CC=gcc
CFLAG=-Wall -Werror
LFLAG= -lcrypto

compile: clientSide.c serverSide.c
	$(CC) clientSide.c -o client $(CFLAG) $(LFLAG)
	$(CC) serverSide.c -o server $(CFLAG) $(LFLAG)
clean:
	rm server
	rm client
