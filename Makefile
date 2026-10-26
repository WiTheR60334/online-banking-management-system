CC      := gcc
CFLAGS  := -std=c11 -O2 -g -Wall -Wextra -Wpedantic -D_POSIX_C_SOURCE=200809L
LDLIBS  := -pthread -lcrypto

COMMON  := store.o net.o

.PHONY: all clean test
all: server client

server: server.o $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

client: client.o net.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

server.o: server.c bank.h net.h
client.o: client.c bank.h net.h
store.o: store.c bank.h
net.o: net.c net.h

tests/test_transactions: tests/test_transactions.c bank.h store.o
	$(CC) $(CFLAGS) -o $@ tests/test_transactions.c store.o $(LDLIBS)

test: tests/test_transactions
	./tests/test_transactions

clean:
	rm -f server client *.o tests/test_transactions
