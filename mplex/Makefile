DEPS =
OBJS = mplex.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) -std=c11

all: $(OBJS)

clean:
	rm -f *.o
