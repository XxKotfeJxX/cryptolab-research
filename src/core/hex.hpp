#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace crypto::core {
std::vector<std::uint8_t> decode_hex(std::string_view text);
std::string encode_hex(std::span<const std::uint8_t> bytes);
}
