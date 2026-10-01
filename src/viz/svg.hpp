#pragma once
#include "core/alphabet.hpp"
#include <string>
#include <string_view>

namespace crypto::viz {
std::string frequency_svg(std::u32string_view before, std::u32string_view after,
                          const core::Alphabet& alphabet, std::string_view source = {});
}
