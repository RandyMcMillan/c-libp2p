SUBMODULES = c-multiaddr c-multihash c-protobuf
COMPONENTS = conn crypto db discovery thirdparty hashmap identify net os peer record routing secio swarm transport utils yamux mplex

export DEBUG = true
export SHARED = true

ROOT= $(shell pwd)
export INCLUDE = -I$(ROOT)/include -I$(ROOT)/c-protobuf -I$(ROOT)/c-multihash/include -I$(ROOT)/c-multiaddr/include
export CFLAGS = $(INCLUDE) -Wall -O0 -fPIC

ifdef DEBUG
CFLAGS += -g3
endif


OBJS = $(shell (find $(COMPONENTS) -name *.o))
LINKER_FLAGS = $(ROOT)/c-multiaddr/libmultiaddr.a $(ROOT)/c-multihash/libmultihash.a $(ROOT)/c-protobuf/protobuf.o $(ROOT)/c-protobuf/varint.o

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
	@case "$$(uname -s)" in \
		Darwin) bad_fmt='Mach-O' ;; \
		*) bad_fmt='ELF' ;; \
	esac; \
	if find $(SUBMODULES) $(COMPONENTS) -type f -name '*.o' -exec file {} + 2>/dev/null | grep -vq "$$bad_fmt"; then \
		echo "  CLEAN stale foreign objects"; \
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
