#pragma once
#include "core/alphabet.hpp"
#include "classic/common.hpp"
#include <string>
#include <string_view>

namespace crypto::classic {
std::u32string caesar(std::u32string_view input, const core::Alphabet& alphabet,
                      long long shift, bool decrypt, InputPolicy policy,
                      const StepCallback& step = {});
}
