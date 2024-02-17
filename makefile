CC=clang
CFLAGS=-Wall -Wextra
CFILES=./src/*.c
OBJFILES=*.o
BIN=cruxpass
MAIN=main.c

all:$(BIN)

$(BIN):$(OBJFILES) 
	$(CC) $(CFLAGS) $(MAIN) -o $@ $^

$(OBJFILES):$(CFILES) 
	$(CC) $(CFLAGS) -c $^

clean:
	rm *.o $(BIN)
