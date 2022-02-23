#
# Copyright 2022 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#

all: generate_hsm_enclave_keys

generate_hsm_enclave_keys: generate_hsm_enclave_keys.c
	gcc -o generate_hsm_enclave_keys generate_hsm_enclave_keys.c \
	  -I /opt/nfast/c/ctd/gcc/include/ \
	  -Wall \
	  -Wstrict-prototypes \
	  -Wmissing-prototypes \
	  -Werror \
	  -L/opt/nfast/c/ctd/gcc/lib \
	  -lnfkm \
	  -lnfstub \
	  -lnflog \
	  -lcutils \
	  -lrqcard \

clean:
	rm -f generate_hsm_enclave_keys

.PHONY: all clean
