#pragma once
#include "classic/common.hpp"
#include "core/alphabet.hpp"
#include <string>
#include <string_view>

namespace crypto::classic {
std::u32string substitution(std::u32string_view input, const core::Alphabet& alphabet,
                            std::u32string_view key, bool decrypt, InputPolicy policy,
                            const StepCallback& step = {});
}
