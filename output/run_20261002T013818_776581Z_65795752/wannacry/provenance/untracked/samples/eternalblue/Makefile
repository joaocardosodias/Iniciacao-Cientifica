CC      = gcc
CFLAGS  = -O2 -Wall -std=c11 -D_GNU_SOURCE -I.
LDFLAGS = -lssl -lcrypto -lcurl
TARGET  = eternalblue

all: $(TARGET)

$(TARGET): $(wildcard *.c) config.h
	$(CC) $(CFLAGS) -o $@ $(wildcard *.c) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
