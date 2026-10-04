#pragma once
#include "classic/common.hpp"
#include <string>
#include <string_view>

namespace crypto::classic {
std::u32string playfair(std::u32string_view input, std::u32string_view key, bool decrypt,
                       const StepCallback& step = {});
}
