CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -I include -I /opt/homebrew/opt/openssl/include -I ../c-protobuf
LDFLAGS = -L /opt/homebrew/opt/openssl/lib -lssl -lcrypto

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

.PHONY: all clean test

all: $(TEST_BIN)

$(TEST_BIN): $(OBJS) $(TEST_SRC)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC) $(OBJS) ../c-protobuf/protobuf.o ../c-protobuf/varint.o $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TEST_BIN)

test: $(TEST_BIN)
	./$(TEST_BIN)
