#include "classic/caesar.hpp"
#include <stdexcept>

namespace crypto::classic {
std::u32string caesar(std::u32string_view input, const core::Alphabet& alphabet,
                      long long shift, bool decrypt, InputPolicy policy,
                      const StepCallback& step) {
    const auto size = alphabet.upper.size();
    if (size == 0 || size != alphabet.lower.size()) throw std::invalid_argument("Невірна абетка");
    // Modulo first: avoiding negation overflow for LLONG_MIN.
    const auto mod = static_cast<long long>(size);
    const auto forward = (shift % mod + mod) % mod;
    const auto effective = decrypt ? (mod - forward) % mod : forward;
    std::u32string output;
    output.reserve(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        const auto index = alphabet.index(input[i]);
        if (index == core::not_found) {
            if (policy == InputPolicy::strict)
                throw std::invalid_argument("Символ поза абеткою на позиції " + std::to_string(i));
            output.push_back(input[i]);
            continue;
        }
        const auto out_index = (index + static_cast<std::size_t>(effective)) % size;
        const auto value = alphabet.upper[out_index];
        output.push_back(value);
        if (step) step(Step{i, index, out_index, input[i], value});
    }
    return output;
}
}
