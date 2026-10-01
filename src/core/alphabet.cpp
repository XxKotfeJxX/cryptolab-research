#include "core/alphabet.hpp"

namespace crypto::core {
char32_t Alphabet::normalize(char32_t cp) const {
    const auto lower_index = lower.find(cp);
    return lower_index != not_found ? upper[lower_index] : cp;
}
std::size_t Alphabet::index(char32_t cp) const { return upper.find(normalize(cp)); }
const Alphabet& alphabet_en() {
    static constexpr Alphabet value{U"ABCDEFGHIJKLMNOPQRSTUVWXYZ", U"abcdefghijklmnopqrstuvwxyz"};
    return value;
}
const Alphabet& alphabet_uk() {
    static constexpr Alphabet value{U"АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ", U"абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"};
    return value;
}
}
