CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -I include -I ../c-protobuf
LDFLAGS =

ifdef HAS_LSQUIC
CFLAGS += -DHAS_LSQUIC -I ../../boringssl/include
LDFLAGS += ../../boringssl/build-c-ipfs/libcrypto.a ../../boringssl/build-c-ipfs/libssl.a
else
CFLAGS += -I /opt/homebrew/opt/openssl/include
LDFLAGS += -L /opt/homebrew/opt/openssl/lib -lssl -lcrypto
endif

SRCS = src/net/multiaddr.c \
       src/net/tcp_dial.c \
       src/peer/peerstore.c \
       src/conn/multistream.c \
       src/conn/noise.c \
       src/conn/yamux.c \
       src/conn/connection.c \
       src/identify/identify_v2.c \
       src/swarm/swarm.c \
       src/utils/logger.c

OBJS = $(SRCS:.c=.o)

TEST_SRC = src/test_main.c
TEST_BIN = test_v2

LIB = libp2p_v2.a

.PHONY: all clean test

all: $(LIB)

$(LIB): $(OBJS)
	ar rcs $@ $(OBJS)

$(TEST_BIN): $(LIB) $(TEST_SRC)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC) $(LIB) ../c-protobuf/protobuf.o ../c-protobuf/varint.o $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TEST_BIN) $(LIB)

test: $(TEST_BIN)
	./$(TEST_BIN)
