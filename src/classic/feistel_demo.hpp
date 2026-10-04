#pragma once
#include <string>
#include <string_view>

namespace crypto::classic {
std::string feistel_demo(std::string_view input, std::string_view key, bool decrypt);
}
