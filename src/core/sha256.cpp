#include "core/sha256.hpp"
#include "core/error.hpp"
#include <bit>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <vector>

namespace crypto::core {
namespace {
bool is_prime(unsigned value) {
    for (unsigned divisor = 2; divisor <= value / divisor; ++divisor)
        if (value % divisor == 0) return false;
    return value >= 2;
}

std::uint32_t fractional_word(long double root) {
    constexpr long double scale = 4294967296.0L;
    return static_cast<std::uint32_t>((root - std::floor(root)) * scale);
}

struct Constants {
    std::array<std::uint32_t, 8> initial{};
    std::array<std::uint32_t, 64> round{};
};

const Constants& constants() {
    // FIPS 180-4 §§4.2.2, 5.3.3: exact fractional bits of prime roots.
    static const Constants values = [] {
        Constants result;
        unsigned prime = 2;
        for (std::size_t i = 0; i < result.round.size(); ++i, ++prime) {
            while (!is_prime(prime)) ++prime;
            if (i < result.initial.size())
                result.initial[i] = fractional_word(std::sqrt(static_cast<long double>(prime)));
            result.round[i] = fractional_word(std::cbrt(static_cast<long double>(prime)));
        }
        if (result.initial[0] != 0x6a09e667u || result.initial[7] != 0x5be0cd19u ||
            result.round[0] != 0x428a2f98u || result.round[63] != 0xc67178f2u)
            throw std::runtime_error("Платформна математика не відтворила константи SHA-256");
        return result;
    }();
    return values;
}

std::uint32_t load_be(const std::uint8_t* bytes) {
    return (std::uint32_t(bytes[0]) << 24) | (std::uint32_t(bytes[1]) << 16) |
           (std::uint32_t(bytes[2]) << 8) | std::uint32_t(bytes[3]);
}

std::uint32_t small0(std::uint32_t value) {
    return std::rotr(value, 7) ^ std::rotr(value, 18) ^ (value >> 3);
}
std::uint32_t small1(std::uint32_t value) {
    return std::rotr(value, 17) ^ std::rotr(value, 19) ^ (value >> 10);
}
std::uint32_t big0(std::uint32_t value) {
    return std::rotr(value, 2) ^ std::rotr(value, 13) ^ std::rotr(value, 22);
}
std::uint32_t big1(std::uint32_t value) {
    return std::rotr(value, 6) ^ std::rotr(value, 11) ^ std::rotr(value, 25);
}
}

std::array<std::uint8_t, 32> sha256(std::string_view bytes) {
    if (bytes.size() > std::numeric_limits<std::uint64_t>::max() / 8)
        throw InputError(ErrorCode::invalid_length, "Вхід SHA-256 перевищує межу довжини");
    const auto bit_length = static_cast<std::uint64_t>(bytes.size()) * 8;
    std::vector<std::uint8_t> padded(bytes.begin(), bytes.end());
    padded.push_back(0x80);
    while (padded.size() % 64 != 56) padded.push_back(0);
    for (int i = 7; i >= 0; --i)
        padded.push_back(static_cast<std::uint8_t>(bit_length >> (i * 8)));

    auto state = constants().initial;
    const auto& k = constants().round;
    for (std::size_t offset = 0; offset < padded.size(); offset += 64) {
        std::array<std::uint32_t, 64> words{};
        for (std::size_t i = 0; i < 16; ++i) words[i] = load_be(padded.data() + offset + i * 4);
        for (std::size_t i = 16; i < 64; ++i)
            words[i] = small1(words[i - 2]) + words[i - 7] + small0(words[i - 15]) + words[i - 16];
        auto [a, b, c, d, e, f, g, h] = state;
        for (std::size_t i = 0; i < 64; ++i) {
            const auto choice = (e & f) ^ (~e & g);
            const auto majority = (a & b) ^ (a & c) ^ (b & c);
            const auto t1 = h + big1(e) + choice + k[i] + words[i];
            const auto t2 = big0(a) + majority;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }
    std::array<std::uint8_t, 32> digest{};
    for (std::size_t i = 0; i < state.size(); ++i)
        for (int j = 0; j < 4; ++j)
            digest[i * 4 + j] = static_cast<std::uint8_t>(state[i] >> (24 - j * 8));
    return digest;
}
}
