#pragma once
#include <cstddef>
#include <functional>

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
}
