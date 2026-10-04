#include "classic/homophonic.hpp"
#include <array>
#include <stdexcept>

namespace crypto::classic {
namespace {
std::array<int, 256> inverse_codes(const core::Alphabet& alphabet, std::string_view key) {
    const auto n = alphabet.upper.size();
    if ((n != 26 && n != 33) || key.size() != 2 * n)
        throw std::invalid_argument("Ключ гомофонної заміни має 2 байти на кожну літеру абетки");
    std::array<int, 256> inverse;
    inverse.fill(-1);
    for (std::size_t i = 0; i < n; ++i) for (std::size_t variant = 0; variant < 2; ++variant) {
        const auto code = static_cast<unsigned char>(key[2 * i + variant]);
        if (inverse[code] != -1) throw std::invalid_argument("Ключ гомофонної заміни містить повторений код");
        inverse[code] = static_cast<int>(i);
    }
    return inverse;
}
}

std::string homophonic_encrypt(std::u32string_view input, const core::Alphabet& alphabet,
                               std::string_view key) {
    inverse_codes(alphabet, key);
    std::string output;
    output.reserve(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        const auto index = alphabet.index(input[i]);
        if (index == core::not_found) throw std::invalid_argument("Вхід гомофонної заміни містить символ поза абеткою");
        output.push_back(key[2 * index + i % 2]);
    }
    return output;
}

std::u32string homophonic_decrypt(std::string_view input, const core::Alphabet& alphabet,
                                  std::string_view key) {
    const auto inverse = inverse_codes(alphabet, key);
    std::u32string output;
    output.reserve(input.size());
    for (char cp : input) {
        const auto index = inverse[static_cast<unsigned char>(cp)];
        if (index < 0) throw std::invalid_argument("Шифротекст гомофонної заміни містить невідомий код");
        output.push_back(alphabet.upper[static_cast<std::size_t>(index)]);
    }
    return output;
}
}
