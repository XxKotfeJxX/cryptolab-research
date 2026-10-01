#pragma once
#include <stdexcept>
#include <string>

namespace crypto::core {
enum class ErrorCode {
    invalid_utf8,
    invalid_hex,
    invalid_alphabet,
    invalid_key,
    invalid_character,
    invalid_length,
    invalid_path,
    io_failure
};

class InputError : public std::invalid_argument {
public:
    InputError(ErrorCode code, const std::string& message) : std::invalid_argument(message), code_(code) {}
    [[nodiscard]] ErrorCode code() const noexcept { return code_; }
private:
    ErrorCode code_;
};

class FileError : public std::runtime_error {
public:
    explicit FileError(const std::string& message) : std::runtime_error(message) {}
    [[nodiscard]] ErrorCode code() const noexcept { return ErrorCode::io_failure; }
};
}
