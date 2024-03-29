CC=gcc
LIBS=-lsodium -lncurses
CFLAGS=-Wall -Wextra -Wformat-security
CFILES=./src/*.c
OBJFILES=*.o
BIN=./bin/cruxpass
TEST=./test/cruxpass
MAIN=main.c

all:$(BIN)

$(BIN):$(OBJFILES)
	$(CC) $(CFLAGS) $(LIBS) $(MAIN) -g -o $@ $^

$(OBJFILES):$(CFILES) 
	$(CC) $(CFLAGS) -c $^

clean:
	rm *.o $(BIN)



