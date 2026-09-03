DEPS =
OBJS = autonat.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) -std=c11

all: $(OBJS)

clean:
	rm -f *.o
