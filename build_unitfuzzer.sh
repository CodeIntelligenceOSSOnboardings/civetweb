#!/usr/bin/env sh

if [ ! -f "out/civetweb_fuzz_target.o" ]; then
	make fuzz_target || exit 1
fi
clang++ -fsanitize=fuzzer,address -I include/ fuzztest/fuzzer.cc out/civetweb_fuzz_target.o -o mg_fuzzer || exit 1
./mg_fuzzer || exit 1
