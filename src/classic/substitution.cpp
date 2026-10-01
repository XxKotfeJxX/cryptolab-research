#include "classic/substitution.hpp"
#include "core/error.hpp"
#include <vector>

namespace crypto::classic {
std::u32string substitution(std::u32string_view input, const core::Alphabet& alphabet,
                            std::u32string_view key, bool decrypt, InputPolicy policy,
                            const StepCallback& step) {
    const auto n = alphabet.upper.size();
    if (n == 0 || alphabet.lower.size() != n)
        throw core::InputError(core::ErrorCode::invalid_alphabet, "Невірна абетка");
    if (key.size() != n)
        throw core::InputError(core::ErrorCode::invalid_length, "Довжина ключа має дорівнювати довжині абетки");
    std::vector<std::size_t> inverse(n, core::not_found);
    for (std::size_t i = 0; i < n; ++i) {
        const auto index = alphabet.index(key[i]);
        if (index == core::not_found || inverse[index] != core::not_found)
            throw core::InputError(core::ErrorCode::invalid_key, "Ключ має бути перестановкою абетки");
        inverse[index] = i;
    }
    std::u32string output;
    output.reserve(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        const auto index = alphabet.index(input[i]);
        if (index == core::not_found) {
            if (policy == InputPolicy::strict)
                throw core::InputError(core::ErrorCode::invalid_character,
                                       "Символ поза абеткою на позиції " + std::to_string(i));
            output.push_back(input[i]);
            continue;
        }
        const auto out_index = decrypt ? inverse[index] : alphabet.index(key[index]);
        const auto value = alphabet.upper[out_index];
        output.push_back(value);
        if (step) step(Step{i, index, out_index, input[i], value});
    }
    return output;
}
}
