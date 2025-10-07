# Makefile for UDP client-server programs

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -pedantic

# Target executables
TARGETS = client 

# Source files
SRCS = client.c

# Object files
OBJS = $(SRCS:.c=.o)

# Default target
all: $(TARGETS)

# Linking the target executables

%: %.o
	$(CC) $(CFLAGS) -o % %.o

# Compiling the source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Cleaning up the build files
clean:
	rm -f $(OBJS) $(TARGETS)

.PHONY: all clean
