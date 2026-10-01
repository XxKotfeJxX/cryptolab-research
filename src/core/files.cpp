#include "core/files.hpp"
#include "core/error.hpp"
#include <atomic>
#include <chrono>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <system_error>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace crypto::core {
namespace {
std::atomic<unsigned long long> sequence{0};

unsigned long long process_id() {
#ifdef _WIN32
    return GetCurrentProcessId();
#else
    return static_cast<unsigned long long>(getpid());
#endif
}

void replace_file(const std::filesystem::path& temporary, const std::filesystem::path& target) {
#ifdef _WIN32
    if (!MoveFileExW(temporary.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        throw FileError("Не вдалося перейменувати тимчасовий файл");
#else
    std::filesystem::rename(temporary, target);
#endif
}
}

std::string read_binary(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw FileError("Не вдалося відкрити вхід: " + path.string());
    std::string data(std::istreambuf_iterator<char>{file}, {});
    if (!file.eof() && file.fail()) throw FileError("Помилка читання: " + path.string());
    return data;
}

bool same_file_or_path(const std::filesystem::path& left, const std::filesystem::path& right) {
    if (left.empty() || right.empty()) return false;
    std::error_code error;
    if (std::filesystem::exists(left, error) && std::filesystem::exists(right, error)) {
        error.clear();
        if (std::filesystem::equivalent(left, right, error) && !error) return true;
    }
    return std::filesystem::weakly_canonical(left) == std::filesystem::weakly_canonical(right);
}

void validate_output_path(const std::filesystem::path& path) {
    if (path.empty()) throw InputError(ErrorCode::invalid_path, "Порожній шлях виходу");
    if (std::filesystem::is_directory(path)) throw InputError(ErrorCode::invalid_path, "Вихід є каталогом");
    const auto parent = path.has_parent_path() ? path.parent_path() : std::filesystem::path(".");
    if (!std::filesystem::is_directory(parent)) throw InputError(ErrorCode::invalid_path, "Батьківський каталог виходу не існує");
}

void write_atomic(const std::filesystem::path& path, const std::string& data) {
    validate_output_path(path);
    const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto counter = sequence.fetch_add(1);
    auto temporary = path;
    temporary += ".tmp." + std::to_string(process_id()) + "." + std::to_string(tick) + "." + std::to_string(counter);
    if (std::filesystem::exists(temporary)) throw FileError("Тимчасовий файл уже існує");
    try {
        {
            std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
            if (!file) throw FileError("Не вдалося створити тимчасовий файл");
            file.write(data.data(), static_cast<std::streamsize>(data.size()));
            file.flush();
            if (!file) throw FileError("Помилка запису тимчасового файлу");
            file.close();
            if (!file) throw FileError("Помилка закриття тимчасового файлу");
        }
        replace_file(temporary, path);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        throw;
    }
}
}
