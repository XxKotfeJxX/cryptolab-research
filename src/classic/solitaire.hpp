#pragma once
#include "classic/common.hpp"
#include <string>
#include <string_view>

namespace crypto::classic {
std::u32string solitaire(std::u32string_view input, std::u32string_view passphrase,
                         bool decrypt, const StepCallback& step = {});
}
