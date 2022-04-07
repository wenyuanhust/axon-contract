TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
AR := $(TARGET)-ar
OBJCOPY := $(TARGET)-objcopy

CFLAGS := -fPIC -O3 -DCKB_C_STDLIB_PRINTF -fno-builtin-printf -fno-builtin-memcmp -nostdinc -nostdlib -nostartfiles -fvisibility=hidden -fdata-sections -ffunction-sections -Wall -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function -Wno-array-bounds -Wno-stringop-overflow -Wno-unused-variable
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
INCLUDE_CFLAGS := -Ideps/ed25519/src -Ideps/ed25519/deps/ckb-c-stdlib/libc -Ideps/secp256k1 -Ideps/secp256k1/src -Ibuild
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3

via-docker:
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make $(ARGS)"
ifeq "$(ARGS)" "build/debug/bitcoin"
	mv build/secp256k1_data ../../build/debug/secp256k1_data
endif

build/debug/cardano: src/cardano.c ed25519
	$(CC) $(CFLAGS) $(LDFLAGS) $(INCLUDE_CFLAGS) -o $@ $< deps/ed25519/build/libed25519.a

build/debug/bitcoin: src/bitcoin.c build/secp256k1_data_info.h
	$(CC) $(CFLAGS) $(LDFLAGS) $(INCLUDE_CFLAGS) -o $@ $<

build/release/cardano: src/cardano.c ed25519
	$(CC) $(CFLAGS) $(LDFLAGS) $(INCLUDE_CFLAGS) -o $@ $< deps/ed25519/build/libed25519.a
	$(OBJCOPY) --strip-debug --strip-all $@

build/release/bitcoin: src/bitcoin.c secp256k1
	$(CC) $(CFLAGS) $(LDFLAGS) $(INCLUDE_CFLAGS) -o $@ $<
	$(OBJCOPY) --strip-debug --strip-all $@

ed25519:
	cd deps/ed25519 && make build/libed25519.a

secp256k1:
	cd deps/secp256k1 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery --host=$(TARGET) && \
		make src/ecmult_static_pre_context.h src/ecmult_static_context.h

build/secp256k1_data_info.h: build/dump_secp256k1_data
	$<

build/dump_secp256k1_data: deps/c/dump_secp256k1_data.c secp256k1
	mkdir -p build
	gcc -Ideps/secp256k1 -Ideps/secp256k1/src -o $@ $<
