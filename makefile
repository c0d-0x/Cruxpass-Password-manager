CC=clang
CFLAGS=-Wall -Wextra
CFILES=*.c
OBJFILES=*.o
BIN=cruxpass

all:$(BIN)

$(BIN):$(OBJFILES) 
	$(CC) $(CFLAGS) -o $@ $^

$(OBJFILES):$(CFILES) 
	$(CC) $(CFLAGS) -c $^

clean:
	rm *.o $(BIN)
