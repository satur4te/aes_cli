# compiler options
CC = gcc
CFLAGS = -Wall -Werror -Wpedantic 

# source and test files
SRC_DIR = src
SOURCES = main.c $(SRC_DIR)/aes.c $(SRC_DIR)/aes_cli.c 
OBJECTS = $(SOURCES:.c=.o)

# targets
all: aes

aes: $(OBJECTS)
	$(CC) $(OBJECTS) -g -o aes

# object files
%.o: %.c
	$(CC) $(CFLAGS) -g -c $< -o $@

.PHONY: clean

clean:
	rm -rf aes $(OBJECTS)
