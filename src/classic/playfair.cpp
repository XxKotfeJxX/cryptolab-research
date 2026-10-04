#include "classic/playfair.hpp"
#include <array>
#include <stdexcept>
#include <utility>

namespace crypto::classic {
namespace {
char32_t normalize(char32_t value) {
    if (value >= U'a' && value <= U'z') value -= U'a' - U'A';
    if (value < U'A' || value > U'Z') throw std::invalid_argument("Плейфер приймає лише ASCII A–Z");
    return value == U'J' ? U'I' : value;
}
char32_t filler(char32_t left) { return left == U'X' ? U'Q' : U'X'; }
}

std::u32string playfair(std::u32string_view input, std::u32string_view key, bool decrypt,
                       const StepCallback& step) {
    if (key.empty()) throw std::invalid_argument("Ключ Плейфера порожній");
    std::array<bool, 26> seen{};
    std::u32string square;
    square.reserve(25);
    auto add = [&](char32_t cp) {
        cp = normalize(cp);
        const auto index = static_cast<std::size_t>(cp - U'A');
        if (!seen[index]) { seen[index] = true; square.push_back(cp); }
    };
    for (char32_t cp : key) add(cp);
    for (char32_t cp = U'A'; cp <= U'Z'; ++cp) if (cp != U'J') add(cp);
    std::array<std::size_t, 26> position{};
    for (std::size_t i = 0; i < square.size(); ++i) position[square[i] - U'A'] = i;

    std::u32string normalized;
    normalized.reserve(input.size());
    for (char32_t cp : input) normalized.push_back(normalize(cp));
    std::u32string prepared;
    if (decrypt) {
        if (normalized.size() % 2 != 0) throw std::invalid_argument("Шифротекст Плейфера має парну довжину");
        prepared = std::move(normalized);
    } else {
        prepared.reserve(normalized.size() + normalized.size() / 2 + 1);
        for (std::size_t i = 0; i < normalized.size();) {
            const char32_t left = normalized[i++];
            prepared.push_back(left);
            if (i == normalized.size() || normalized[i] == left) prepared.push_back(filler(left));
            else prepared.push_back(normalized[i++]);
        }
    }

    std::u32string output;
    output.reserve(prepared.size());
    const std::size_t shift = decrypt ? 4 : 1;
    for (std::size_t i = 0; i < prepared.size(); i += 2) {
        const auto a = position[prepared[i] - U'A'];
        const auto b = position[prepared[i + 1] - U'A'];
        const auto ar = a / 5, ac = a % 5, br = b / 5, bc = b % 5;
        std::size_t ao, bo;
        if (ar == br) { ao = 5 * ar + (ac + shift) % 5; bo = 5 * br + (bc + shift) % 5; }
        else if (ac == bc) { ao = 5 * ((ar + shift) % 5) + ac; bo = 5 * ((br + shift) % 5) + bc; }
        else { ao = 5 * ar + bc; bo = 5 * br + ac; }
        output.push_back(square[ao]);
        output.push_back(square[bo]);
        if (step) {
            step({i, static_cast<std::size_t>(prepared[i] - U'A'),
                  static_cast<std::size_t>(square[ao] - U'A'), prepared[i], square[ao]});
            step({i + 1, static_cast<std::size_t>(prepared[i + 1] - U'A'),
                  static_cast<std::size_t>(square[bo] - U'A'), prepared[i + 1], square[bo]});
        }
    }
    return output;
}
}
