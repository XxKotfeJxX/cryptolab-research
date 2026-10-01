#pragma once
#include "core/alphabet.hpp"
#include <cstddef>
#include <functional>
#include <string>
#include <string_view>

namespace crypto::classic {
enum class InputPolicy { strict, passthrough };
struct Step {
    std::size_t codepoint_position;
    std::size_t input_index;
    std::size_t output_index;
    char32_t input;
    char32_t output;
};
using StepCallback = std::function<void(const Step&)>;
std::u32string caesar(std::u32string_view input, const core::Alphabet& alphabet,
                      long long shift, bool decrypt, InputPolicy policy,
                      const StepCallback& step = {});
}
