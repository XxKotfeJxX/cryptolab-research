#include "classic/grille.hpp"
#include <algorithm>
#include <array>
#include <stdexcept>

namespace crypto::classic {
namespace {
std::size_t hex_digit(char32_t cp) {
    if (cp >= U'0' && cp <= U'9') return static_cast<std::size_t>(cp - U'0');
    if (cp >= U'a' && cp <= U'f') return static_cast<std::size_t>(cp - U'a' + 10);
    if (cp >= U'A' && cp <= U'F') return static_cast<std::size_t>(cp - U'A' + 10);
    throw std::invalid_argument("Ключ решітки має містити лише чотири hex-цифри");
}
std::size_t rotate_clockwise(std::size_t p) { return (p % 4) * 4 + 3 - p / 4; }
}

std::u32string grille(std::u32string_view input, const core::Alphabet& alphabet,
                     std::u32string_view mask, bool decrypt, const StepCallback& step) {
    if (mask.size() != 4) throw std::invalid_argument("Ключ решітки має містити чотири hex-цифри");
    if (input.size() % 16 != 0) throw std::invalid_argument("Вхід решітки має складатися з блоків по 16 літер");
    std::array<std::size_t, 4> holes{};
    for (std::size_t i = 0; i < 4; ++i) holes[i] = hex_digit(mask[i]);
    std::array<bool, 16> visited{};
    std::array<std::array<std::size_t, 4>, 4> order{};
    for (std::size_t turn = 0; turn < 4; ++turn) {
        std::sort(holes.begin(), holes.end());
        order[turn] = holes;
        for (const auto p : holes) {
            if (visited[p]) throw std::invalid_argument("Маска решітки повторно відкриває комірку");
            visited[p] = true;
        }
        for (auto& p : holes) p = rotate_clockwise(p);
    }
    std::u32string normalized;
    normalized.reserve(input.size());
    for (char32_t cp : input) {
        const auto index = alphabet.index(cp);
        if (index == core::not_found) throw std::invalid_argument("Вхід решітки містить символ поза абеткою");
        normalized.push_back(alphabet.upper[index]);
    }
    std::u32string output(normalized.size(), U'\0');
    for (std::size_t base = 0; base < normalized.size(); base += 16) {
        std::size_t cursor = 0;
        for (const auto& turn : order) for (const auto p : turn) {
            if (decrypt) {
                output[base + cursor] = normalized[base + p];
                if (step) step({base + p, alphabet.index(normalized[base + p]),
                                alphabet.index(output[base + cursor]), normalized[base + p], output[base + cursor]});
            } else {
                output[base + p] = normalized[base + cursor];
                if (step) step({base + cursor, alphabet.index(normalized[base + cursor]),
                                alphabet.index(output[base + p]), normalized[base + cursor], output[base + p]});
            }
            ++cursor;
        }
    }
    return output;
}
}
