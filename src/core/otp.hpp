#pragma once
#include <string>
#include <string_view>

namespace crypto::core {
std::string otp_xor(std::string_view input, std::string_view key);
}
