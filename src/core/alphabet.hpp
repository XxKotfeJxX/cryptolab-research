#pragma once
#include <cstddef>
#include <string_view>

namespace crypto::core {
struct Alphabet {
    std::u32string_view upper;
    std::u32string_view lower;
    char32_t normalize(char32_t cp) const;
    std::size_t index(char32_t cp) const;
};
inline constexpr std::size_t not_found = std::u32string_view::npos;
const Alphabet& alphabet_en();
const Alphabet& alphabet_uk();
}
