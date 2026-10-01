#include "core/sha256.hpp"
#include "core/error.hpp"
#include <bit>
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

// Four base-2^32 limbs suffice for p*2^96 (p <= 311) and candidate cubes.
using Wide = std::array<std::uint32_t, 4>;

Wide multiply(Wide left, std::uint64_t right) {
    const std::array<std::uint32_t, 2> digits = {
        static_cast<std::uint32_t>(right), static_cast<std::uint32_t>(right >> 32)};
    Wide result{};
    for (std::size_t i = 0; i < left.size(); ++i) {
        std::uint64_t carry = 0;
        for (std::size_t j = 0; j < digits.size() && i + j < result.size(); ++j) {
            const auto sum = std::uint64_t(left[i]) * digits[j] + result[i + j] + carry;
            result[i + j] = static_cast<std::uint32_t>(sum);
            carry = sum >> 32;
        }
        for (std::size_t k = i + digits.size(); carry && k < result.size(); ++k) {
            const auto sum = std::uint64_t(result[k]) + carry;
            result[k] = static_cast<std::uint32_t>(sum);
            carry = sum >> 32;
        }
    }
    return result;
}

bool at_most(Wide left, Wide right) {
    for (std::size_t i = left.size(); i-- > 0;) {
        if (left[i] != right[i]) return left[i] < right[i];
    }
    return true;
}

std::uint32_t fractional_root_word(unsigned prime, unsigned degree) {
    // floor(root_degree(prime) * 2^32) mod 2^32, using integers only.
    Wide target{};
    target[degree] = prime;
    std::uint64_t low = 0;
    std::uint64_t high = std::uint64_t{8} << 32; // > sqrt(19) and cbrt(311).
    while (low + 1 < high) {
        const auto midpoint = low + (high - low) / 2;
        Wide power = {static_cast<std::uint32_t>(midpoint),
                      static_cast<std::uint32_t>(midpoint >> 32), 0, 0};
        for (unsigned exponent = 1; exponent < degree; ++exponent)
            power = multiply(power, midpoint);
        if (at_most(power, target)) low = midpoint;
        else high = midpoint;
    }
    return static_cast<std::uint32_t>(low);
}

struct Constants {
    std::array<std::uint32_t, 8> initial{};
    std::array<std::uint32_t, 64> round{};
};

// FIPS 180-4 (2015), §§5.3.3 and 4.2.2. These published words check every
// generated bit on each compiler; they are not used to derive the words.
constexpr std::array<std::uint32_t, 8> published_initial = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
constexpr std::array<std::uint32_t, 64> published_round = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

const Constants& constants() {
    // FIPS 180-4 §§4.2.2, 5.3.3: exact fractional bits of prime roots.
    static const Constants values = [] {
        Constants result;
        unsigned prime = 2;
        for (std::size_t i = 0; i < result.round.size(); ++i, ++prime) {
            while (!is_prime(prime)) ++prime;
            if (i < result.initial.size())
                result.initial[i] = fractional_root_word(prime, 2);
            result.round[i] = fractional_root_word(prime, 3);
        }
        if (result.initial != published_initial || result.round != published_round)
            throw std::runtime_error("Згенеровані константи SHA-256 не збігаються з FIPS 180-4");
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
