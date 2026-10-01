#pragma once
#include <filesystem>
#include <string>

namespace crypto::core {
std::string read_binary(const std::filesystem::path& path);
bool same_file_or_path(const std::filesystem::path& left, const std::filesystem::path& right);
void validate_output_path(const std::filesystem::path& path);
void write_atomic(const std::filesystem::path& path, const std::string& data);
}
