.PHONY: all

C_FILES = $(wildcard *.c)
NAME    = pwntest
CFLAGS  += -g -O0 -z execstack -fno-stack-protector -Wno-format-security -fPIC -pie --std=c11 -D_GNU_SOURCE
CFLAGS_RELRO = $(CFLAGS) -Wl,-z,relro,-z,now
LDFLAGS += -ldl -lpthread

ALL = i386-pwntest amd64-pwntest arm-pwntest aarch64-pwntest thumb-pwntest powerpc-pwntest

all: $(ALL)

clean: $(ALL)
	for file in $^ ; do \
		rm -rf $$file*; \
	done

i386-pwntest: $(C_FILES)
	$(eval CC := gcc -m32)
	$(CC) $(CFLAGS)       -Wl,-z,norelro      $^ -o $@ $(LDFLAGS)
	$(CC) $(CFLAGS_RELRO) -Wl,-z,relro        $^ -o $@-partial $(LDFLAGS)
	$(CC) $(CFLAGS_RELRO) -Wl,-z,relro,-z,now $^ -o $@-relro $(LDFLAGS)

amd64-pwntest: $(C_FILES)
	$(eval CC := gcc -m64)
	$(CC) $(CFLAGS)       -Wl,-z,norelro      $^ -o $@ $(LDFLAGS)
	$(CC) $(CFLAGS_RELRO) -Wl,-z,relro        $^ -o $@-partial $(LDFLAGS)
	$(CC) $(CFLAGS_RELRO) -Wl,-z,relro,-z,now $^ -o $@-relro $(LDFLAGS)

arm-pwntest: $(C_FILES)
	$(eval CC := arm-linux-gnueabihf-gcc-4.8)
	$(CC) $(CFLAGS)       -Wl,-z,norelro      $^ -o $@ $(LDFLAGS)
	$(CC) $(CFLAGS_RELRO) -Wl,-z,relro        $^ -o $@-partial $(LDFLAGS)
	$(CC) $(CFLAGS_RELRO) -Wl,-z,relro,-z,now $^ -o $@-relro $(LDFLAGS)

thumb-pwntest: $(C_FILES)
	$(eval CC := arm-linux-gnueabihf-gcc-4.8 -mthumb)
	$(CC) $(CFLAGS)       -Wl,-z,norelro      $^ -o $@ $(LDFLAGS)
	$(CC) $(CFLAGS_RELRO) -Wl,-z,relro        $^ -o $@-partial $(LDFLAGS)
	$(CC) $(CFLAGS_RELRO) -Wl,-z,relro,-z,now $^ -o $@-relro $(LDFLAGS)

powerpc-pwntest: $(C_FILES)
	$(eval CC := powerpc-linux-gnu-gcc-4.8)
	$(CC) $(CFLAGS)       -Wl,-z,norelro      $^ -o $@ $(LDFLAGS)
	$(CC) $(CFLAGS_RELRO) -Wl,-z,relro        $^ -o $@-partial $(LDFLAGS)
	$(CC) $(CFLAGS_RELRO) -Wl,-z,relro,-z,now $^ -o $@-relro $(LDFLAGS)

aarch64-pwntest: $(C_FILES)
	$(eval CC := aarch64-linux-gnu-gcc-4.8)
	$(CC) $(CFLAGS)       -Wl,-z,norelro      $^ -o $@ $(LDFLAGS)
	$(CC) $(CFLAGS_RELRO) -Wl,-z,relro        $^ -o $@-partial $(LDFLAGS)
	$(CC) $(CFLAGS_RELRO) -Wl,-z,relro,-z,now $^ -o $@-relro $(LDFLAGS)

#mips-pwntest: $(C_FILES)qq
#	gcc-4.3-mips-linux-gnu $(CFLAGS) $^ -o $@

