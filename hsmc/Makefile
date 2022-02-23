#
# Copyright 2022 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#

NATIVE_CC=gcc
NATIVE_LD=gcc
NATIVE_AR=ar
HSM_CC=/opt/nfast/gcc/bin/powerpc-codesafe-linux-gnu-gcc
HSM_AR=/opt/nfast/gcc/bin/powerpc-codesafe-linux-gnu-ar
AFL_CC=afl-clang

# These flags mostly pulled from nCipher-provided CMake files.
INCLUDE_DIRS= \
    -Inoise-c/include \
    -Inoise-c/src/crypto \
    -Ilua \
    -ISipHash \
## /INCLUDE_DIRS
COMMON_FLAGS= \
    -O2 \
    -mpowerpc \
    -mcpu=e5500 \
    -mno-toc \
    -mbig-endian \
    -mhard-float \
    -mno-multiple \
    -mno-string \
    -meabi \
    -mprototype \
    -mstrict-align \
    -memb \
    -fno-builtin \
    -DNF_CROSSCC_PPC_GCC=1 \
    -DHAVE_ISATTY \
    -DHAVE_STRSIGNAL \
## /COMMON_FLAGS
HSM_CFLAGS= \
    -Wall \
    -Wpointer-arith \
    -Wwrite-strings \
    -Wstrict-prototypes \
    -Wmissing-prototypes \
    -Werror \
    -I/opt/nfast/c/csd/include-see/module \
    -I/opt/nfast/c/csd/include-see/module/glibsee \
    -I/opt/nfast/c/csd/include-see/cutils \
    -std=c99 \
    $(INCLUDE_DIRS) \
    $(COMMON_FLAGS) \
## /HSM_CFLAGS
LD=/opt/nfast/gcc/bin/powerpc-codesafe-linux-gnu-gcc
LDFLAGS= \
    $(COMMON_FLAGS) \
    -pthread \
    -Wl,-wrap=noise_rand_bytes \
## /LDFLAGS
LDLIBS= \
    /opt/nfast/c/csd/lib-ppc-linux-gcc/seelib.a \
    /opt/nfast/c/csd/lib-ppc-linux-gcc/libstdmar.a \
    /opt/nfast/c/csd/lib-ppc-linux-gcc/rtlib/librtusr.a \
    -lm \
## /LDLIBS
NATIVE_CFLAGS= \
    -g \
    -Wall \
    -Werror \
    -std=c99 \
    -DDEBUG \
    -DLOGOUT=stderr \
    $(INCLUDE_DIRS) \
## /NATIVE_CFLAGS
TEST_CFLAGS= \
    $(NATIVE_CFLAGS) \
    -fprofile-arcs \
    -ftest-coverage \
## /TEST_CFLAGS
NATIVE_LDFLAGS= \
    -lm \
## /NATIVE_LDFLAGS
TEST_LDFLAGS= \
    $(NATIVE_LDFLAGS) \
    -fprofile-arcs \
    -ftest-coverage \
    -lgcov \
    --coverage \
## /TEST_LDFLAGS
    
all: \
    doxygen \
    build/bin/hsm_enclave_onhsm \
    build/bin/hsm_enclave_onhsm_debug \
    build/bin/hsm_enclave_test \
    build/bin/hsm_enclave_native \
    check \
    valgrind \
    coverage \
## /all

# We write all of our artifacts into subdirectories of a local ./build dir.
# Make all of those directories with this rule.
build/.dir:
	mkdir -p build/bin build/hsmlib build/nativelib build/native build/hsm build/hsm_debug build/test build/doc build/afl build/afllib build/docker
	touch build/.dir

check: build/bin/hsm_enclave_test
	find build/test/ -type f | grep gcda | xargs --no-run-if-empty rm
	./build/bin/hsm_enclave_test

coverage: check
	./gencodecoverage.sh

valgrind: build/bin/hsm_enclave_test
	valgrind --tool=memcheck --leak-check=full --error-exitcode=3 -s --track-origins=yes ./build/bin/hsm_enclave_test

doxygen: | build/.dir
	doxygen doxygen.config

aflfuzz: build/bin/hsm_enclave_afl
	./aflfuzz.sh

aflfuzz_nolua: build/bin/hsm_enclave_afl_nolua
	SUFFIX=_nolua ./aflfuzz.sh

clean:
	rm -rfv build
	(cd lua && git clean -fx)
	(cd noise-c && git clean -fx)

# We can build each object currently in 3 ways:
### Build for running natively
build/test/%.o: %.c *.h | build/.dir
	$(NATIVE_CC) -c -o $@ $< $(TEST_CFLAGS)
build/native/%.o: %.c *.h | build/.dir
	$(NATIVE_CC) -c -o $@ $< $(NATIVE_CFLAGS)
### Build for running on the HSM
build/hsm/%.o: %.c *.h | build/.dir
	$(HSM_CC) -c -o $@ $< $(HSM_CFLAGS)
### Build for running on the HSM, but with debug logs turned on
build/hsm_debug/%.o: %.c *.h | build/.dir
	$(HSM_CC) -c -o $@ $< $(HSM_CFLAGS) -DDEBUG
### Build for AFL fuzzer
build/afl/%.o: %.c *.h | build/.dir
	$(AFL_CC) -c -o $@ $< $(NATIVE_CFLAGS)

# Common objects for native and HSM binaries.
HSM_ENCLAVE_OBJS= \
    dlog \
    error \
    command \
    commandqueue \
    channel \
    processstate \
    process \
    hsm_enclave \
    funcstubs \
    hmac_sha2 \
    noise \
    fixedmap \
    sandbox \
    crypt \
## /HSM_ENCLAVE_OBJS

# Objects utilized only by native binaries
HSM_ENCLAVE_NATIVE_OBJS= \
    env_native \
    crypt_native \
## HSM_ENCLAVE_NATIVE_OBJS

# Objects utilized only by HSM binaries
HSM_ENCLAVE_HSM_OBJS= \
    env_hsm \
    dh-curve25519 \
    crypt_hsm \
## HSM_ENCLAVE_HSM_OBJS

# Static libraries
HSM_ENCLAVE_LIBS= \
    noiseprotocol \
    lua \
    sip \
## /HSM_ENCLAVE_LIBS

sandbox.c: sandbox.py sandbox.lua
	./sandbox.py

build/bin/hsm_enclave_test: \
   build/test/hsm_enclave_test.o \
   $(foreach OBJ,$(HSM_ENCLAVE_OBJS),build/test/$(OBJ).o) \
   $(foreach OBJ,$(HSM_ENCLAVE_NATIVE_OBJS),build/test/$(OBJ).o) \
   $(foreach LIB,$(HSM_ENCLAVE_LIBS),build/nativelib/lib$(LIB).a) \
   | build/.dir
	$(NATIVE_LD) -o $@ $^ $(TEST_LDFLAGS)

build/bin/hsm_enclave_native: \
    build/native/hsm_enclave_native.o \
    $(foreach OBJ,$(HSM_ENCLAVE_OBJS),build/native/$(OBJ).o) \
    $(foreach OBJ,$(HSM_ENCLAVE_NATIVE_OBJS),build/native/$(OBJ).o) \
    $(foreach LIB,$(HSM_ENCLAVE_LIBS),build/nativelib/lib$(LIB).a) \
    | build/.dir
	$(NATIVE_LD) -o $@ $^ $(NATIVE_LDFLAGS)

build/bin/hsm_enclave_onhsm: \
    build/hsm/hsm_enclave_onhsm.o \
    $(foreach OBJ,$(HSM_ENCLAVE_OBJS),build/hsm/$(OBJ).o) \
    $(foreach OBJ,$(HSM_ENCLAVE_HSM_OBJS),build/hsm/$(OBJ).o) \
    $(foreach LIB,$(HSM_ENCLAVE_LIBS),build/hsmlib/lib$(LIB).a) \
    | build/.dir
	$(LD) -o $@ $^ $(LDFLAGS) $(LDLIBS)

build/bin/hsm_enclave_onhsm_debug: \
    build/hsm_debug/hsm_enclave_onhsm.o \
    $(foreach OBJ,$(HSM_ENCLAVE_OBJS),build/hsm_debug/$(OBJ).o) \
    $(foreach OBJ,$(HSM_ENCLAVE_HSM_OBJS),build/hsm_debug/$(OBJ).o) \
    $(foreach LIB,$(HSM_ENCLAVE_LIBS),build/hsmlib/lib$(LIB).a) \
    | build/.dir
	$(LD) -o $@ $^ $(LDFLAGS) $(LDLIBS)

build/bin/hsm_enclave_afl: \
    build/afl/hsm_enclave_afl.o \
    $(foreach OBJ,$(HSM_ENCLAVE_OBJS),build/afl/$(OBJ).o) \
    $(foreach OBJ,$(HSM_ENCLAVE_NATIVE_OBJS),build/afl/$(OBJ).o) \
    $(foreach LIB,$(HSM_ENCLAVE_LIBS),build/afllib/lib$(LIB).a) \
    | build/.dir
	$(AFL_CC) -o $@ $^ $(NATIVE_LDFLAGS)

build/bin/hsm_enclave_afl_nolua: \
    build/afl/hsm_enclave_afl_nolua.o \
    $(foreach OBJ,$(HSM_ENCLAVE_OBJS),build/afl/$(OBJ).o) \
    $(foreach OBJ,$(HSM_ENCLAVE_NATIVE_OBJS),build/afl/$(OBJ).o) \
    $(foreach LIB,$(HSM_ENCLAVE_LIBS),build/afllib/lib$(LIB).a) \
    | build/.dir
	$(AFL_CC) -o $@ $^ $(NATIVE_LDFLAGS)

.PHONY: clean all check doxygen valgrind aflfuzz aflfuzz_nolua docker repeatable

# From here down, we're building our other library dependencies ($(HSM_ENCLAVE_LIBS)).
# Note that we add a dependency from hsmlib/*.a->nativelib/*.a.  This is
# to allow compilation of the nativelib in areas where the hsmlib is not
# viable, and to make sure that, since they're both built in the same subdirs,
# they're not run in parallel.

.NO_PARALLEL: \
  build/hsmlib/libnoiseprotocol.a \
  build/nativelib/libnoiseprotocol.a \
  build/afllib/libnoiseprotocol.a \
  build/hsmlib/liblua.a \
  build/nativelib/liblua.a \
  build/afllib/liblua.a

build/hsmlib/libnoiseprotocol.a: | build/.dir
	(cd noise-c && \
	 (git clean -fx || make clean || true) && \
	 ./autogen.sh && \
	 CFLAGS="$(COMMON_FLAGS)" CC=/opt/nfast/gcc/bin/powerpc-codesafe-linux-gnu-gcc ./configure --with-ed448-arch=arch_32 --without-libsodium --without-openssl --host=powerpc)
	$(MAKE) -C noise-c -j
	cp -v noise-c/src/protocol/libnoiseprotocol.a build/hsmlib/libnoiseprotocol.a

build/nativelib/libnoiseprotocol.a: | build/.dir
	(cd noise-c && \
	 (git clean -fx || make clean || true) && \
	 ./autogen.sh && \
	 ./configure)
	$(MAKE) -C noise-c -j
	cp -v noise-c/src/protocol/libnoiseprotocol.a build/nativelib/libnoiseprotocol.a

build/afllib/libnoiseprotocol.a: | build/.dir
	(cd noise-c && \
	 (git clean -fx || make clean || true) && \
	 ./autogen.sh && \
	 CC=$(AFL_CC) ./configure)
	$(MAKE) -C noise-c -j
	cp -v noise-c/src/protocol/libnoiseprotocol.a build/afllib/libnoiseprotocol.a

build/hsmlib/liblua.a: | build/.dir
	(cd lua && (git clean -fx || make clean || true))
	$(MAKE) -C lua CC=$(HSM_CC) CFLAGS="$(COMMON_FLAGS) -std=c99" liblua.a -j
	cp -v lua/liblua.a build/hsmlib/liblua.a

build/nativelib/liblua.a: | build/.dir
	(cd lua && (git clean -fx || make clean || true))
	$(MAKE) -C lua liblua.a -j
	cp -v lua/liblua.a build/nativelib/liblua.a

build/afllib/liblua.a: | build/.dir
	(cd lua && (git clean -fx || make clean || true))
	$(MAKE) -C lua CC=$(AFL_CC) liblua.a -j
	cp -v lua/liblua.a build/afllib/liblua.a

build/hsmlib/libsip.a: | build/.dir
	$(HSM_CC) $(HSM_CFLAGS) -I SipHash -c -o build/hsmlib/halfsiphash.o SipHash/halfsiphash.c
	$(HSM_AR) rcs build/hsmlib/libsip.a build/hsmlib/halfsiphash.o

build/nativelib/libsip.a: | build/.dir
	$(NATIVE_CC) -I SipHash -c -o build/nativelib/halfsiphash.o SipHash/halfsiphash.c
	$(NATIVE_AR) rcs build/nativelib/libsip.a build/nativelib/halfsiphash.o

build/afllib/libsip.a: | build/.dir
	$(AFL_CC) -I SipHash -c -o build/afllib/halfsiphash.o SipHash/halfsiphash.c
	$(NATIVE_AR) rcs build/afllib/libsip.a build/afllib/halfsiphash.o

build/docker/nfast.sha256: | build/.dir
	find /opt/nfast/c/csd -type f | sort | xargs sha256sum > build/docker/nfast_csd.sha256
	find /opt/nfast/gcc -type f | sort | xargs sha256sum > build/docker/nfast_gcc.sha256
	sha256sum build/docker/nfast_csd.sha256 build/docker/nfast_gcc.sha256 > build/docker/nfast.sha256
	cat build/docker/nfast.sha256

docker: sandbox.c | build/docker/nfast.sha256
	docker build --build-arg UID=$$(id -u) --build-arg GID=$$(id -g) \
	  -t hsm-enclave-builder ./docker
	docker run -it --rm --cap-add SYS_PTRACE --cap-add CAP_SYS_ADMIN \
		-v `pwd`/:/home/builder/ \
		-v /opt/nfast/c/csd:/opt/nfast/c/csd \
		-v /opt/nfast/gcc:/opt/nfast/gcc \
		-v `pwd`/build/docker/:/home/builder/build/ \
		hsm-enclave-builder
	sha256sum build/docker/bin/*

build/bin/hsm_enclave_onhsm.repeatable: docker
	cp build/docker/bin/hsm_enclave_onhsm build/bin/hsm_enclave_onhsm.repeatable

build/bin/hsm_enclave_onhsm_debug.repeatable: docker
	cp build/docker/bin/hsm_enclave_onhsm_debug build/bin/hsm_enclave_onhsm_debug.repeatable

repeatable: build/bin/hsm_enclave_onhsm.repeatable build/bin/hsm_enclave_onhsm_debug.repeatable
