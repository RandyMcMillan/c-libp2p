CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -I include -I /opt/homebrew/opt/openssl/include
LDFLAGS = -L /opt/homebrew/opt/openssl/lib -lssl -lcrypto

SRCS = src/net/multiaddr.c \
       src/net/tcp_dial.c \
       src/peer/peerstore.c \
       src/conn/multistream.c \
       src/conn/secio.c \
       src/conn/yamux.c \
       src/conn/connection.c \
       src/swarm/swarm.c \
       src/utils/logger.c

OBJS = $(SRCS:.c=.o)

TEST_SRC = src/test_main.c
TEST_BIN = test_v2

.PHONY: all clean test

all: $(TEST_BIN)

$(TEST_BIN): $(OBJS) $(TEST_SRC)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TEST_BIN)

test: $(TEST_BIN)
	./$(TEST_BIN)
