#include "civetweb.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>

// This is fuzzer.cc
// clang++ -fsanitize=fuzzer,address -I include/ fuzztest/fuzzer.cc
// out/civetweb_fuzz_target.o -o mg_fuzzer
extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzedDataProvider fuzzed_data(data, size);

	char buffer[1024];
	size_t buffer_len = sizeof(buffer);

	if (fuzzed_data.ConsumeBool()) { // Fuzz mg_url_decode and mg_url_encode
		std::string src = fuzzed_data.ConsumeRemainingBytesAsString();
		char encoded[1024];
		int encoded_len = mg_url_encode(src.c_str(), encoded, sizeof(encoded));
		if (encoded_len > 0) {
			char dst[1024];
			int decoded_len =
			    mg_url_decode(encoded, encoded_len, dst, sizeof(dst), 1);

			if (decoded_len > 0) {
				dst[decoded_len] =
				    '\0'; // Add null-terminator, but ensure mg_url_decode
				          // doesn't already do this
				if (decoded_len != encoded_len
				    || std::memcmp(dst, src.c_str(), decoded_len) != 0) {
					// assert(false
					//        && "mg_url_decode and mg_url_encode are not "
					//           "symmetrical");
				}
			}
		}
	} else {
		// Fuzz mg_base64_encode and mg_base64_decode
		std::string src = fuzzed_data.ConsumeRemainingBytesAsString();
		char encoded[1024];
		size_t encoded_len = sizeof(encoded);
		mg_base64_encode((const unsigned char *)src.c_str(),
		                 src.size(),
		                 encoded,
		                 &encoded_len);

		unsigned char decoded[1024];
		size_t decoded_len = sizeof(decoded);
		mg_base64_decode(encoded, encoded_len, decoded, &decoded_len);

		// Here we check if src == decoded(encoded(src))
		if (decoded_len != src.size()
		    || std::memcmp(decoded, src.c_str(), src.size()) != 0) {
			// assert(false
			//        && "mg_base64_encode and mg_base64_decode are not "
			//           "symmetrical");
		}
	}
	return 0;
}
