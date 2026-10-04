#pragma once
#include "core/alphabet.hpp"
#include <string>
#include <string_view>

namespace crypto::classic {
std::string homophonic_encrypt(std::u32string_view input, const core::Alphabet& alphabet,
                               std::string_view key);
std::u32string homophonic_decrypt(std::string_view input, const core::Alphabet& alphabet,
                                  std::string_view key);
}
