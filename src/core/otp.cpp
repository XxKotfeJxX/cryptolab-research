#include "core/otp.hpp"
#include <stdexcept>

namespace crypto::core {
std::string otp_xor(std::string_view input, std::string_view key) {
    if (input.size() != key.size()) throw std::invalid_argument("Ключ OTP має мати рівно довжину входу");
    std::string output(input.size(), '\0');
    for (std::size_t i = 0; i < input.size(); ++i)
        output[i] = static_cast<char>(static_cast<unsigned char>(input[i]) ^ static_cast<unsigned char>(key[i]));
    return output;
}
}
