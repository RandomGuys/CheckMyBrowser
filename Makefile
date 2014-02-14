CFLAGS=-std=c99 -g -pthread 
LFLAGS=-lssl -lcrypto -lmagic

all: ServerHTTPS
	
ServerHTTPS: ServerHTTPS.c
	$(CC) $(CFLAGS) SocketTCP.c ServerHTTPS.c -o ServerHTTPS $(LFLAGS)
