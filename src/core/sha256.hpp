#pragma once
#include <array>
#include <cstdint>
#include <string_view>

namespace crypto::core {
std::array<std::uint8_t, 32> sha256(std::string_view bytes);
}
