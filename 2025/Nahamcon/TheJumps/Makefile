SHELL := /bin/bash
CC ?= gcc

DESTDIR := initramfs
CPIO := initramfs.cpio.gz
TARGET := exploit
OUT := $(TARGET)

SRCS := exploit.c

CPPFLAGS := -I.

CFLAGS := -Wall -masm=intel -static -std=c2x
LDFLAGS := -static -luring -lpthread

.PHONY: all compress decompress clean

all: $(OUT)

$(OUT): $(SRCS)


compress: all
	cd $(DESTDIR) && \
	find . -print0 \
	| cpio --null -ov --format=newc -R root \
	| gzip -9 > ../$(CPIO)

decompress:
	mkdir -p $(DESTDIR) && \
	cd $(DESTDIR) && \
	cp ../$(CPIO) . && \
	gunzip ./$(CPIO) && \
	cpio -idm < ./$(basename $(CPIO))
	rm -f $(basename $(CPIO))

clean:
	rm -f $(OUT) || true
