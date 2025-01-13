# compiler options
CC = gcc
CFLAGS = -Wall -Werror -Wpedantic 

# targets
all: 
	$(CC) main.c $(CFLAGS) -o aes

.PHONY: clean

clean:
	rm -rf aes
