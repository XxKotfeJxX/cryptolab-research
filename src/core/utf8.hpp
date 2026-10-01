#pragma once
#include <string>
#include <string_view>

namespace crypto::core {
std::u32string decode_utf8(std::string_view bytes);
std::string encode_utf8(std::u32string_view text);
}
