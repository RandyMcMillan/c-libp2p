SUBMODULES = c-multiaddr c-multihash c-protobuf
COMPONENTS = conn crypto db thirdparty hashmap identify net os peer record routing secio swarm transport utils yamux

export DEBUG = true
export SHARED = true

ROOT= $(shell pwd)
export INCLUDE = -I$(ROOT)/include -I$(ROOT)/c-protobuf -I$(ROOT)/c-multihash/include -I$(ROOT)/c-multiaddr/include
export CFLAGS = $(INCLUDE) -Wall -O0 -fPIC

ifdef DEBUG
CFLAGS += -g3
endif


OBJS = $(shell (find $(COMPONENTS) -name *.o))
LINKER_FLAGS = c-multiaddr/libmultiaddr.a c-multihash/libmultihash.a c-protobuf/protobuf.o c-protobuf/varint.o

all: test

link: compile
	$(AR) rcs libp2p.a $(OBJS) $(LINKER_FLAGS)
#ifdef SHARED
ifeq ($(shell uname -s),Darwin)
	gcc -dynamiclib -Wl,-install_name,@rpath/libp2p.dylib -o libp2p.dylib $(OBJS) $(LINKER_FLAGS)
else
	gcc -shared -o libp2p.so $(OBJS) $(LINKER_FLAGS)
endif
#endif

prepare:
	@if [ "$$(uname -s)" = "Darwin" ] && find $(SUBMODULES) $(COMPONENTS) -name '*.o' -exec file {} + 2>/dev/null | grep -vq 'Mach-O'; then \
		echo "  CLEAN stale non-Mach-O objects"; \
		$(MAKE) clean; \
	fi

compile: prepare
	$(foreach dir,$(SUBMODULES), $(MAKE) -C $(dir) all ;)
	$(foreach dir,$(COMPONENTS), $(MAKE) -C $(dir) all ;)

test: link
	make -C test all;

rebuild: clean all

clean:
	$(foreach dir,$(SUBMODULES), $(MAKE) -C $(dir) clean ;)
	$(foreach dir,$(COMPONENTS), $(MAKE) -C $(dir) clean ;)
	make -C test clean
