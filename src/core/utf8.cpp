#include "core/utf8.hpp"
#include "core/error.hpp"

namespace crypto::core {
std::u32string decode_utf8(std::string_view bytes) {
    std::u32string output;
    output.reserve(bytes.size());
    for (std::size_t i = 0; i < bytes.size();) {
        const auto first = static_cast<unsigned char>(bytes[i]);
        char32_t value = 0;
        std::size_t length = 0;
        if (first < 0x80) { value = first; length = 1; }
        else if (first >= 0xC2 && first <= 0xDF) { value = first & 0x1F; length = 2; }
        else if (first >= 0xE0 && first <= 0xEF) { value = first & 0x0F; length = 3; }
        else if (first >= 0xF0 && first <= 0xF4) { value = first & 0x07; length = 4; }
        else throw InputError(ErrorCode::invalid_utf8, "Невірний початковий байт UTF-8 на зсуві " + std::to_string(i));
        if (i + length > bytes.size()) throw InputError(ErrorCode::invalid_utf8, "Обрізаний UTF-8 на зсуві " + std::to_string(i));
        for (std::size_t j = 1; j < length; ++j) {
            const auto byte = static_cast<unsigned char>(bytes[i + j]);
            if ((byte & 0xC0) != 0x80) throw InputError(ErrorCode::invalid_utf8, "Невірний байт UTF-8 на зсуві " + std::to_string(i + j));
            value = (value << 6) | (byte & 0x3F);
        }
        if ((length == 2 && value < 0x80) || (length == 3 && value < 0x800) ||
            (length == 4 && value < 0x10000) || (value >= 0xD800 && value <= 0xDFFF) ||
            value > 0x10FFFF) throw InputError(ErrorCode::invalid_utf8, "Недопустима кодова точка UTF-8 на зсуві " + std::to_string(i));
        output.push_back(value);
        i += length;
    }
    return output;
}

std::string encode_utf8(std::u32string_view text) {
    std::string output;
    for (const char32_t cp : text) {
        if (cp >= 0xD800 && cp <= 0xDFFF) throw InputError(ErrorCode::invalid_utf8, "Сурогатна кодова точка");
        if (cp > 0x10FFFF) throw InputError(ErrorCode::invalid_utf8, "Кодова точка за межами Unicode");
        if (cp < 0x80) output.push_back(static_cast<char>(cp));
        else if (cp < 0x800) {
            output.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            output.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            output.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            output.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            output.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            output.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return output;
}
}
