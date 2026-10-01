#include "classic/vigenere.hpp"
#include "core/error.hpp"
#include <vector>

namespace crypto::classic {
std::u32string vigenere(std::u32string_view input, const core::Alphabet& alphabet,
                        std::u32string_view key, bool decrypt, InputPolicy policy,
                        const StepCallback& step) {
    const auto n = alphabet.upper.size();
    if (n == 0 || alphabet.lower.size() != n)
        throw core::InputError(core::ErrorCode::invalid_alphabet, "Невірна абетка");
    if (key.empty()) throw core::InputError(core::ErrorCode::invalid_length, "Ключ Віженера порожній");
    std::vector<std::size_t> shifts;
    shifts.reserve(key.size());
    for (const auto cp : key) {
        const auto index = alphabet.index(cp);
        if (index == core::not_found)
            throw core::InputError(core::ErrorCode::invalid_key, "Символ ключа поза абеткою");
        shifts.push_back(index);
    }
    std::u32string output;
    output.reserve(input.size());
    std::size_t letter_number = 0;
    for (std::size_t i = 0; i < input.size(); ++i) {
        const auto index = alphabet.index(input[i]);
        if (index == core::not_found) {
            if (policy == InputPolicy::strict)
                throw core::InputError(core::ErrorCode::invalid_character,
                                       "Символ поза абеткою на позиції " + std::to_string(i));
            output.push_back(input[i]);
            continue;
        }
        const auto shift = shifts[letter_number % shifts.size()];
        const auto out_index = decrypt ? (index + n - shift) % n : (index + shift) % n;
        const auto value = alphabet.upper[out_index];
        output.push_back(value);
        if (step) step(Step{i, index, out_index, input[i], value});
        ++letter_number;
    }
    return output;
}
}
