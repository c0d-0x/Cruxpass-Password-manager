# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Wformat-security
LIBS = -lsodium -lncurses
MAIN = main.c

# Source and object files
CFILES = ./src/*.c
OBJFILES = *.o  

# Target binaries
BIN = ./bin/cruxpass

# Installation prefix (default /usr/local)
PREFIX ?= /usr/local

# Installation directory
DESTDIR = /usr/local/share/cruxpass

# Main target
all: $(BIN)

# Build executable
$(BIN): $(OBJFILES)
	$(CC) $(CFLAGS) $(LIBS) $(MAIN) -o $@ $^

# Compile source files
$(OBJFILES): $(CFILES)
	$(CC) $(CFLAGS) -c $^ 

# Install target
install: $(BIN)
	install -d $(PREFIX)/bin  # Combined directory creation
	install -d $(DESTDIR)
	install -m 0755 $(BIN) $(PREFIX)/bin

# Phony target (no actual command)
.PHONY: clean uninstall

# Clean target
clean:
	rm -f *.o $(BIN)

# Uninstall target
uninstall:
	rm -rf $(DESTDIR)
	sudo rm $(PREFIX)/cruxpass

