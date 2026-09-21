#pragma once

#include <stddef.h>

namespace lp {

unsigned char* ImageBase();
size_t ImageSize();
bool ImageBytesMatch(unsigned long rva, const unsigned char* bytes, size_t len);
bool ImageFileDigest(unsigned long long* size, unsigned char hash[32]);

}
