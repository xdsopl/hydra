
# WebAssembly HYDRA module for self-healing erasure coding
# Copyright 2026 Ahmet Inan <xdsopl@gmail.com>

CC = clang
CXX = clang++
CFLAGS = -std=c89 -W -Wall -pedantic -O2 -Iquirks -ffreestanding -fvisibility=hidden --target=wasm32
CXXFLAGS = -std=c++11 -W -Wall -O2 -fno-exceptions -fno-rtti -ffreestanding -fvisibility=hidden --target=wasm32
LDFLAGS = -nostdlib -Wl,--export-dynamic,--no-entry
BLAKE2 = -Iblake2_ref
CODE = -Icode_ref

assets/hydra.wasm.gz: temp/hydra.wasm
	gzip -n -c $< > $@

.PHONY: webserver
webserver:
	go run tools/webserver.go

temp/hydra.wasm: temp/string.o temp/blake2s-ref.o temp/hydra.o temp/cme.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

temp/blake2s-ref.o: blake2_ref/blake2s-ref.c blake2_ref/blake2.h blake2_ref/blake2-impl.h quirks/string.h
	$(CC) $(CFLAGS) $(BLAKE2) -c -o $@ $<

temp/hydra.o: module/hydra.c quirks/string.h blake2_ref/blake2.h
	$(CC) $(CFLAGS) $(BLAKE2) -c -o $@ $<

temp/string.o: quirks/string.c quirks/string.h
	$(CC) $(CFLAGS) -c -o $@ $<

temp/cme.o: module/cme.cc code_ref/cauchy_prime_field_erasure_coding.hh code_ref/mersenne_packing.hh code_ref/prime_field.hh
	$(CXX) $(CXXFLAGS) $(CODE) -c -o $@ $<

.PHONY: clean

clean:
	rm -f temp/*.o

