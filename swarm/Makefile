DEPS = 
OBJS = swarm.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) -D_DEFAULT_SOURCE -std=c99

all: $(OBJS)

clean:
	rm -f *.o
