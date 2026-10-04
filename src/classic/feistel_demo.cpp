#include "classic/feistel_demo.hpp"
#include <stdexcept>

namespace crypto::classic {
namespace {
unsigned char round_function(unsigned char right, unsigned char key) {
    const auto rotated = static_cast<unsigned char>((right << 1) | (right >> 7));
    return static_cast<unsigned char>(rotated ^ key);
}
}

std::string feistel_demo(std::string_view input, std::string_view key, bool decrypt) {
    if (key.size() != 4) throw std::invalid_argument("Демонстраційний ключ Фейстеля має рівно 4 байти");
    if (input.size() % 2 != 0) throw std::invalid_argument("Вхід Фейстеля має складатися з 16-бітних блоків");
    std::string output(input.size(), '\0');
    for (std::size_t offset = 0; offset < input.size(); offset += 2) {
        auto left = static_cast<unsigned char>(input[offset]);
        auto right = static_cast<unsigned char>(input[offset + 1]);
        if (decrypt) {
            for (int round = 3; round >= 0; --round) {
                const auto previous_left = static_cast<unsigned char>(right ^ round_function(left, static_cast<unsigned char>(key[round])));
                right = left;
                left = previous_left;
            }
        } else {
            for (std::size_t round = 0; round < 4; ++round) {
                const auto next_right = static_cast<unsigned char>(left ^ round_function(right, static_cast<unsigned char>(key[round])));
                left = right;
                right = next_right;
            }
        }
        output[offset] = static_cast<char>(left);
        output[offset + 1] = static_cast<char>(right);
    }
    return output;
}
}
