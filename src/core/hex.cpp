#include "core/hex.hpp"
#include "core/error.hpp"

namespace crypto::core {
namespace {
int digit(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}
}
std::vector<std::uint8_t> decode_hex(std::string_view text) {
    if (text.size() % 2 != 0) throw InputError(ErrorCode::invalid_hex, "Непарна кількість hex-цифр");
    std::vector<std::uint8_t> result;
    result.reserve(text.size() / 2);
    for (std::size_t i = 0; i < text.size(); i += 2) {
        const int high = digit(text[i]), low = digit(text[i + 1]);
        if (high < 0 || low < 0) throw InputError(ErrorCode::invalid_hex, "Недопустима hex-цифра на зсуві " + std::to_string(i));
        result.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return result;
}
std::string encode_hex(std::span<const std::uint8_t> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}
}
