
# WebAssembly HYDRA module for self-healing erasure coding
# Copyright 2026 Ahmet Inan <xdsopl@gmail.com>

CC = clang
CFLAGS = -ffreestanding -fvisibility=hidden --target=wasm32
LDFLAGS = -nostdlib -Wl,--export-dynamic,--no-entry

CFLAGS += -std=c89 -W -Wall -O2 -Iquirks
BLAKE2 = -Iblake2_ref

assets/hydra.wasm.gz: assets/hydra.wasm
	gzip -f -n $<

.PHONY: webserver
webserver:
	go run tools/webserver.go

assets/hydra.wasm: temp/string.o temp/blake2s-ref.o temp/hydra.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

temp/blake2s-ref.o: blake2_ref/blake2s-ref.c blake2_ref/blake2.h blake2_ref/blake2-impl.h quirks/string.h
	$(CC) $(CFLAGS) $(BLAKE2) -c -o $@ $<

temp/hydra.o: module/hydra.c quirks/string.h blake2_ref/blake2.h
	$(CC) $(CFLAGS) $(BLAKE2) -c -o $@ $<

temp/string.o: quirks/string.c quirks/string.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -f temp/*.o

