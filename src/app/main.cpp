#include "classic/caesar.hpp"
#include "core/alphabet.hpp"
#include "core/utf8.hpp"
#include "viz/svg.hpp"
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>

namespace {
std::string read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("Не вдалося відкрити вхід: " + path);
    std::string data(std::istreambuf_iterator<char>{file}, {});
    if (!file.eof() && file.fail()) throw std::runtime_error("Помилка читання: " + path);
    return data;
}
void write_file(const std::string& path, const std::string& data) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) throw std::runtime_error("Не вдалося відкрити вихід: " + path);
    file.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!file) throw std::runtime_error("Помилка запису: " + path);
}
long long integer(const std::string& text) {
    std::size_t pos = 0;
    const auto result = std::stoll(text, &pos, 10);
    if (pos != text.size()) throw std::invalid_argument("Зсув має бути цілим числом");
    return result;
}
std::size_t nonnegative(const std::string& text) {
    if (text.empty() || text[0] == '-') throw std::invalid_argument("Ліміт кроків має бути невід’ємним");
    std::size_t pos = 0;
    const auto result = std::stoull(text, &pos, 10);
    if (pos != text.size() || result > std::numeric_limits<std::size_t>::max())
        throw std::invalid_argument("Невірний ліміт кроків");
    return static_cast<std::size_t>(result);
}
void usage() {
    std::cerr << "Використання: cryptolab caesar encrypt|decrypt --alphabet en|uk --shift N "
                 "--in FILE --out FILE [--policy strict|passthrough] [--steps N|all] [--chart SVG]\n";
}
}

int main(int argc, char** argv) {
    try {
        if (argc < 4 || std::string(argv[1]) != "caesar" ||
            (std::string(argv[2]) != "encrypt" && std::string(argv[2]) != "decrypt")) {
            usage(); return 2;
        }
        const bool decrypt = std::string(argv[2]) == "decrypt";
        std::string alphabet_name, input_path, output_path, policy_name = "strict", chart_path;
        long long shift = 0;
        bool have_shift = false, trace = false;
        std::size_t trace_limit = 0;
        for (int i = 3; i < argc; ++i) {
            const std::string name = argv[i];
            if (i + 1 == argc) throw std::invalid_argument("Відсутнє значення параметра: " + name);
            const std::string value = argv[++i];
            if (name == "--alphabet") alphabet_name = value;
            else if (name == "--shift") { shift = integer(value); have_shift = true; }
            else if (name == "--in") input_path = value;
            else if (name == "--out") output_path = value;
            else if (name == "--policy") policy_name = value;
            else if (name == "--chart") chart_path = value;
            else if (name == "--steps") {
                trace = true;
                trace_limit = value == "all" ? std::numeric_limits<std::size_t>::max() : nonnegative(value);
            } else throw std::invalid_argument("Невідомий параметр: " + name);
        }
        if ((alphabet_name != "en" && alphabet_name != "uk") || !have_shift || input_path.empty() || output_path.empty()) {
            usage(); return 2;
        }
        if (policy_name != "strict" && policy_name != "passthrough")
            throw std::invalid_argument("Політика має бути strict або passthrough");
        if (input_path == output_path || (!chart_path.empty() && (chart_path == input_path || chart_path == output_path)))
            throw std::invalid_argument("Шляхи входу, виходу й графіка мають бути різними");
        const auto& alphabet = alphabet_name == "en" ? crypto::core::alphabet_en() : crypto::core::alphabet_uk();
        const auto input = crypto::core::decode_utf8(read_file(input_path));
        std::size_t shown = 0;
        const crypto::classic::StepCallback step = trace ? crypto::classic::StepCallback{
            [&](const crypto::classic::Step& s) {
                if (shown++ >= trace_limit) return;
                std::cout << "позиція=" << s.codepoint_position << " "
                    << crypto::core::encode_utf8(std::u32string(1, s.input)) << "[" << s.input_index << "] -> "
                    << crypto::core::encode_utf8(std::u32string(1, s.output)) << "[" << s.output_index << "]\n";
            }} : crypto::classic::StepCallback{};
        const auto output = crypto::classic::caesar(input, alphabet, shift, decrypt,
            policy_name == "strict" ? crypto::classic::InputPolicy::strict : crypto::classic::InputPolicy::passthrough, step);
        const auto encoded = crypto::core::encode_utf8(output);
        const auto chart = chart_path.empty() ? std::string{} : crypto::viz::frequency_svg(input, output, alphabet);
        write_file(output_path, encoded);
        if (!chart_path.empty()) write_file(chart_path, chart);
        std::cout << "Готово: " << output.size() << " кодових точок, " << encoded.size() << " байтів UTF-8.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Помилка: " << error.what() << '\n';
        return 1;
    }
}
