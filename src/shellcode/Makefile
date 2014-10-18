.PHONY: all

C_FILES = $(wildcard *.c)
DIRNAME = $(shell basename $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST)))))
CFLAGS  += -g -O0 -z execstack -fno-stack-protector -Wno-format-security -fPIC -pie --std=c11 -D_GNU_SOURCE
LDFLAGS += -ldl -lpthread

ALL =  $(DIRNAME)-i386 $(DIRNAME)-amd64 $(DIRNAME)-arm $(DIRNAME)-aarch64 $(DIRNAME)-thumb $(DIRNAME)-powerpc

all: $(ALL)

clean: $(ALL)
	rm -rf $^

$(DIRNAME)-i386: $(C_FILES)
	gcc -m32 $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(DIRNAME)-amd64: $(C_FILES)
	gcc -m64 $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(DIRNAME)-arm: $(C_FILES)
	arm-linux-gnueabihf-gcc-4.8 $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(DIRNAME)-thumb: $(C_FILES)
	arm-linux-gnueabihf-gcc-4.8 $(CFLAGS) -mthumb $^ -o $@ $(LDFLAGS)

$(DIRNAME)-powerpc: $(C_FILES)
	powerpc-linux-gnu-gcc-4.8 $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(DIRNAME)-aarch64: $(C_FILES)
	aarch64-linux-gnu-gcc-4.8 $(CFLAGS) $^ -o $@ $(LDFLAGS)

#$(DIRNAME)-mips: $(C_FILES)qq
#	gcc-4.3-mips-linux-gnu $(CFLAGS) $^ -o $@

