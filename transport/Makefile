CC = gcc
CFLAGS = -O0 -I../include -I../c-protobuf -I../c-multihash/include -I../c-multiaddr/include -Wall -std=gnu99 -fPIC

ifdef DEBUG
CFLAGS += -g3
endif

DEPS =
OBJS = quic.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: $(OBJS)

clean:
	rm -f *.o
