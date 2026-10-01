#include "classic/hill.hpp"
#include "core/error.hpp"
#include <array>
#include <vector>

namespace crypto::classic {
namespace {
using Matrix = std::array<int, 9>;

int mod(int value, int modulus) {
    const int remainder = value % modulus;
    return remainder < 0 ? remainder + modulus : remainder;
}

Matrix inverse_matrix(const Matrix& a, int modulus) {
    const int det = a[0] * (a[4] * a[8] - a[5] * a[7])
                  - a[1] * (a[3] * a[8] - a[5] * a[6])
                  + a[2] * (a[3] * a[7] - a[4] * a[6]);
    int inverse_det = 0;
    for (int candidate = 1; candidate < modulus; ++candidate)
        if (mod(det * candidate, modulus) == 1) { inverse_det = candidate; break; }
    if (inverse_det == 0)
        throw core::InputError(core::ErrorCode::invalid_key, "Матриця ключа не має оберненої за модулем абетки");
    const Matrix cofactors = {
        a[4] * a[8] - a[5] * a[7], a[5] * a[6] - a[3] * a[8], a[3] * a[7] - a[4] * a[6],
        a[2] * a[7] - a[1] * a[8], a[0] * a[8] - a[2] * a[6], a[1] * a[6] - a[0] * a[7],
        a[1] * a[5] - a[2] * a[4], a[2] * a[3] - a[0] * a[5], a[0] * a[4] - a[1] * a[3]
    };
    Matrix inverse{};
    for (int row = 0; row < 3; ++row)
        for (int column = 0; column < 3; ++column)
            inverse[row * 3 + column] = mod(inverse_det * cofactors[column * 3 + row], modulus);
    return inverse;
}
}

std::u32string hill3(std::u32string_view input, const core::Alphabet& alphabet,
                     std::u32string_view key, bool decrypt, InputPolicy policy,
                     const StepCallback& step) {
    const auto n = alphabet.upper.size();
    if ((n != 26 && n != 33) || alphabet.lower.size() != n)
        throw core::InputError(core::ErrorCode::invalid_alphabet, "Для Гілла потрібна абетка EN або UK");
    if (key.size() != 9)
        throw core::InputError(core::ErrorCode::invalid_length, "Ключ Гілла мусить містити 9 літер");
    Matrix matrix{};
    for (std::size_t i = 0; i < 9; ++i) {
        const auto index = alphabet.index(key[i]);
        if (index == core::not_found)
            throw core::InputError(core::ErrorCode::invalid_key, "Символ ключа поза абеткою");
        matrix[i] = static_cast<int>(index);
    }
    const auto inverted = inverse_matrix(matrix, static_cast<int>(n));
    const auto& active = decrypt ? inverted : matrix;
    std::vector<std::size_t> positions;
    std::vector<int> values;
    positions.reserve(input.size());
    values.reserve(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        const auto index = alphabet.index(input[i]);
        if (index == core::not_found) {
            if (policy == InputPolicy::strict)
                throw core::InputError(core::ErrorCode::invalid_character,
                                       "Символ поза абеткою на позиції " + std::to_string(i));
        } else {
            positions.push_back(i);
            values.push_back(static_cast<int>(index));
        }
    }
    if (values.size() % 3 != 0)
        throw core::InputError(core::ErrorCode::invalid_length, "Неповний блок Гілла: потрібні трійки літер");
    std::u32string output(input);
    for (std::size_t block = 0; block < values.size(); block += 3) {
        for (int row = 0; row < 3; ++row) {
            const auto out_index = mod(active[row * 3] * values[block] +
                                       active[row * 3 + 1] * values[block + 1] +
                                       active[row * 3 + 2] * values[block + 2], static_cast<int>(n));
            const auto position = positions[block + row];
            const auto value = alphabet.upper[static_cast<std::size_t>(out_index)];
            output[position] = value;
            if (step) step(Step{position, static_cast<std::size_t>(values[block + row]),
                                static_cast<std::size_t>(out_index), input[position], value});
        }
    }
    return output;
}
}
