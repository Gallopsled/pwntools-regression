.PHONY: all

C_FILES = $(wildcard *.c)
NAME    = pwntest
CFLAGS  += -g -O0 -z execstack -fno-stack-protector -Wno-format-security -fPIC -pie --std=c11 -D_GNU_SOURCE
CFLAGS_RELRO = $(CFLAGS) -Wl,-z,relro,-z,now
LDFLAGS += -ldl -lpthread

ALL = i386-pwntest amd64-pwntest arm-pwntest aarch64-pwntest thumb-pwntest powerpc-pwntest

all: $(ALL)

clean: $(ALL)
	rm -rf $^

i386-pwntest: $(C_FILES)
	gcc -m32 $(CFLAGS)       -Wl,-z,norelro      $^ -o $@ $(LDFLAGS)
	gcc -m32 $(CFLAGS_RELRO) -Wl,-z,relro        $^ -o $@-partial $(LDFLAGS)
	gcc -m32 $(CFLAGS_RELRO) -Wl,-z,relro,-z,now $^ -o $@-relro $(LDFLAGS)

amd64-pwntest: $(C_FILES)
	gcc -m64 $(CFLAGS) -Wl,-z,norelro      $^ -o $@         $(LDFLAGS)
	gcc -m64 $(CFLAGS) -Wl,-z,relro        $^ -o $@-partial $(LDFLAGS)
	gcc -m64 $(CFLAGS) -Wl,-z,relro,-z,now $^ -o $@-relro   $(LDFLAGS)

arm-pwntest: $(C_FILES)
	arm-linux-gnueabihf-gcc-4.8 $(CFLAGS) $^ -o $@ $(LDFLAGS)

thumb-pwntest: $(C_FILES)
	arm-linux-gnueabihf-gcc-4.8 $(CFLAGS) -mthumb $^ -o $@ $(LDFLAGS)

powerpc-pwntest: $(C_FILES)
	powerpc-linux-gnu-gcc-4.8 $(CFLAGS) $^ -o $@ $(LDFLAGS)

aarch64-pwntest: $(C_FILES)
	aarch64-linux-gnu-gcc-4.8 $(CFLAGS) $^ -o $@ $(LDFLAGS)

#mips-pwntest: $(C_FILES)qq
#	gcc-4.3-mips-linux-gnu $(CFLAGS) $^ -o $@

