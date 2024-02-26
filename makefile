CC=clang
LIBS=-lsodium -lncurses
CFLAGS=-Wall -Wextra
CFILES=./src/*.c
OBJFILES=*.o
BIN=./bin/cruxpass
MAIN=main.c

all:$(BIN)

$(BIN):$(OBJFILES) 
	$(CC) $(CFLAGS) $(LIBS) $(MAIN) -o $@ $^

$(OBJFILES):$(CFILES) 
	$(CC) $(CFLAGS) -c $^

clean:
	rm *.o $(BIN)
