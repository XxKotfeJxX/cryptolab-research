#include "classic/caesar.hpp"
#include "classic/feistel_demo.hpp"
#include "classic/grille.hpp"
#include "classic/hill.hpp"
#include "classic/playfair.hpp"
#include "classic/substitution.hpp"
#include "classic/vigenere.hpp"
#include "core/alphabet.hpp"
#include "core/files.hpp"
#include "core/otp.hpp"
#include "core/sha256.hpp"
#include "core/utf8.hpp"
#include "viz/svg.hpp"
#include <charconv>
#include <iostream>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {
long long integer(const std::string& text) {
    if (text.empty()) throw std::invalid_argument("Зсув має бути цілим 64-бітним числом");
    long long result = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), result);
    if (error != std::errc{} || end != text.data() + text.size())
        throw std::invalid_argument("Зсув має бути цілим 64-бітним числом");
    return result;
}
std::size_t nonnegative(const std::string& text) {
    if (text.empty() || text[0] == '-') throw std::invalid_argument("Ліміт кроків має бути невід’ємним");
    std::size_t result = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), result);
    if (error != std::errc{} || end != text.data() + text.size())
        throw std::invalid_argument("Невірний ліміт кроків");
    return result;
}
void usage() {
    std::cerr << "Використання: cryptolab caesar encrypt|decrypt --alphabet en|uk --shift N "
                 "--in FILE --out FILE [--policy strict|passthrough] [--steps N|all] [--trace FILE] [--chart SVG]\n"
                 "              cryptolab substitution encrypt|decrypt --alphabet en|uk --key-file FILE "
                 "--in FILE --out FILE [--policy strict|passthrough] [--steps N|all] [--trace FILE] [--chart SVG]\n"
                 "              cryptolab vigenere encrypt|decrypt --alphabet en|uk --key-file FILE "
                 "--in FILE --out FILE [--policy strict|passthrough] [--steps N|all] [--trace FILE] [--chart SVG]\n"
                 "              cryptolab hill3 encrypt|decrypt --alphabet en|uk --key-file FILE "
                 "--in FILE --out FILE [--policy strict|passthrough] [--steps N|all] [--trace FILE] [--chart SVG]\n"
                 "              cryptolab playfair encrypt|decrypt --alphabet en --key-file FILE "
                 "--in FILE --out FILE [--steps N|all] [--trace FILE] [--chart SVG]\n"
                 "              cryptolab grille encrypt|decrypt --alphabet en|uk --key-file FILE "
                 "--in FILE --out FILE [--steps N|all] [--trace FILE] [--chart SVG]\n"
                 "              cryptolab sha256 hash --in FILE --out FILE (32 байти)\n";
    std::cerr << "              cryptolab otp xor --in FILE --key-file FILE --out FILE (сирі байти)\n";
    std::cerr << "              cryptolab feistel-demo encrypt|decrypt --in FILE --key-file FILE --out FILE (сирі 16-бітні блоки)\n";
}

int hash_cli(int argc, char** argv) {
    if (argc != 7 || std::string(argv[2]) != "hash") { usage(); return 2; }
    std::string input_path, output_path;
    std::set<std::string> seen;
    for (int i = 3; i < argc; i += 2) {
        const std::string name = argv[i];
        if (!seen.insert(name).second) throw std::invalid_argument("Повторений параметр: " + name);
        if (name == "--in") input_path = argv[i + 1];
        else if (name == "--out") output_path = argv[i + 1];
        else throw std::invalid_argument("Невідомий параметр: " + name);
    }
    if (input_path.empty() || output_path.empty()) { usage(); return 2; }
    if (crypto::core::same_file_or_path(input_path, output_path))
        throw std::invalid_argument("Шляхи входу й виходу мають бути різними");
    crypto::core::validate_output_path(output_path);
    const auto digest = crypto::core::sha256(crypto::core::read_binary(input_path));
    crypto::core::write_atomic(output_path, std::string(digest.begin(), digest.end()));
    std::cout << "Готово: SHA-256, 32 байти.\n";
    return 0;
}
int keyed_binary_cli(int argc, char** argv) {
    const bool otp = std::string(argv[1]) == "otp";
    const std::string operation = argc >= 3 ? argv[2] : "";
    if (argc != 9 || (otp ? operation != "xor" : (operation != "encrypt" && operation != "decrypt"))) {
        usage(); return 2;
    }
    std::string input_path, key_path, output_path;
    std::set<std::string> seen;
    for (int i = 3; i < argc; i += 2) {
        const std::string name = argv[i];
        if (!seen.insert(name).second) throw std::invalid_argument("Повторений параметр: " + name);
        if (name == "--in") input_path = argv[i + 1];
        else if (name == "--key-file") key_path = argv[i + 1];
        else if (name == "--out") output_path = argv[i + 1];
        else throw std::invalid_argument("Невідомий параметр: " + name);
    }
    if (input_path.empty() || key_path.empty() || output_path.empty()) { usage(); return 2; }
    if (crypto::core::same_file_or_path(input_path, output_path) ||
        crypto::core::same_file_or_path(input_path, key_path) ||
        crypto::core::same_file_or_path(key_path, output_path))
        throw std::invalid_argument("Шляхи входу, ключа й виходу мають бути різними");
    crypto::core::validate_output_path(output_path);
    const auto input = crypto::core::read_binary(input_path);
    const auto key = crypto::core::read_binary(key_path);
    const auto output = otp ? crypto::core::otp_xor(input, key) :
        crypto::classic::feistel_demo(input, key, operation == "decrypt");
    crypto::core::write_atomic(output_path, output);
    std::cout << "Готово: " << (otp ? "OTP XOR" : "мережа Фейстеля") << ", " << output.size() << " байтів.\n";
    return 0;
}
}

int main(int argc, char** argv) {
    try {
        if (argc >= 2 && std::string(argv[1]) == "sha256") return hash_cli(argc, argv);
        if (argc >= 2 && (std::string(argv[1]) == "otp" || std::string(argv[1]) == "feistel-demo"))
            return keyed_binary_cli(argc, argv);
        if (argc < 4 || (std::string(argv[1]) != "caesar" && std::string(argv[1]) != "substitution" &&
                         std::string(argv[1]) != "vigenere" && std::string(argv[1]) != "hill3" &&
                         std::string(argv[1]) != "playfair" && std::string(argv[1]) != "grille") ||
            (std::string(argv[2]) != "encrypt" && std::string(argv[2]) != "decrypt")) {
            usage(); return 2;
        }
        const bool is_substitution = std::string(argv[1]) == "substitution";
        const bool is_vigenere = std::string(argv[1]) == "vigenere";
        const bool is_hill = std::string(argv[1]) == "hill3";
        const bool is_playfair = std::string(argv[1]) == "playfair";
        const bool is_grille = std::string(argv[1]) == "grille";
        const bool uses_key_file = is_substitution || is_vigenere || is_hill || is_playfair || is_grille;
        const bool decrypt = std::string(argv[2]) == "decrypt";
        std::string alphabet_name, input_path, output_path, key_path, policy_name = "strict", chart_path, trace_path;
        long long shift = 0;
        bool have_shift = false, trace = false;
        std::size_t trace_limit = 0;
        std::set<std::string> seen;
        for (int i = 3; i < argc; ++i) {
            const std::string name = argv[i];
            if (i + 1 == argc) throw std::invalid_argument("Відсутнє значення параметра: " + name);
            const std::string value = argv[++i];
            if (!seen.insert(name).second) throw std::invalid_argument("Повторений параметр: " + name);
            if (name == "--alphabet") alphabet_name = value;
            else if (name == "--shift") { shift = integer(value); have_shift = true; }
            else if (name == "--in") input_path = value;
            else if (name == "--out") output_path = value;
            else if (name == "--key-file") key_path = value;
            else if (name == "--policy") policy_name = value;
            else if (name == "--chart") {
                if (value.empty()) throw std::invalid_argument("Порожній шлях графіка");
                chart_path = value;
            }
            else if (name == "--trace") {
                if (value.empty()) throw std::invalid_argument("Порожній шлях траси");
                trace_path = value;
            }
            else if (name == "--steps") {
                trace = true;
                trace_limit = value == "all" ? std::numeric_limits<std::size_t>::max() : nonnegative(value);
            } else throw std::invalid_argument("Невідомий параметр: " + name);
        }
        if ((alphabet_name != "en" && alphabet_name != "uk") || input_path.empty() || output_path.empty() ||
            (uses_key_file ? (key_path.empty() || have_shift) : (!have_shift || !key_path.empty()))) {
            usage(); return 2;
        }
        if (policy_name != "strict" && policy_name != "passthrough")
            throw std::invalid_argument("Політика має бути strict або passthrough");
        if (is_playfair && (alphabet_name != "en" || policy_name != "strict"))
            throw std::invalid_argument("Плейфер має лише профіль en/strict");
        if (is_grille && policy_name != "strict")
            throw std::invalid_argument("Решітка має лише політику strict");
        if (!trace_path.empty() && !trace) throw std::invalid_argument("Для --trace потрібно вказати --steps");
        const std::string paths[] = {input_path, output_path, key_path, chart_path, trace_path};
        for (std::size_t i = 0; i < 5; ++i)
            for (std::size_t j = i + 1; j < 5; ++j)
                if (crypto::core::same_file_or_path(paths[i], paths[j]))
                    throw std::invalid_argument("Шляхи входу, ключа, виходу, графіка й траси мають бути різними");
        crypto::core::validate_output_path(output_path);
        if (!chart_path.empty()) crypto::core::validate_output_path(chart_path);
        if (!trace_path.empty()) crypto::core::validate_output_path(trace_path);
        const auto& alphabet = alphabet_name == "en" ? crypto::core::alphabet_en() : crypto::core::alphabet_uk();
        const auto input = crypto::core::decode_utf8(crypto::core::read_binary(input_path));
        const auto key = uses_key_file ? crypto::core::decode_utf8(crypto::core::read_binary(key_path)) : std::u32string{};
        std::size_t shown = 0;
        std::ostringstream steps;
        const crypto::classic::StepCallback step = trace ? crypto::classic::StepCallback{
            [&](const crypto::classic::Step& s) {
                if (shown >= trace_limit) return;
                ++shown;
                steps << "позиція=" << s.codepoint_position << " "
                    << crypto::core::encode_utf8(std::u32string(1, s.input)) << "[" << s.input_index << "] -> "
                    << crypto::core::encode_utf8(std::u32string(1, s.output)) << "[" << s.output_index << "]\n";
            }} : crypto::classic::StepCallback{};
        const auto policy = policy_name == "strict" ? crypto::classic::InputPolicy::strict : crypto::classic::InputPolicy::passthrough;
        std::u32string output;
        if (is_substitution) output = crypto::classic::substitution(input, alphabet, key, decrypt, policy, step);
        else if (is_vigenere) output = crypto::classic::vigenere(input, alphabet, key, decrypt, policy, step);
        else if (is_hill) output = crypto::classic::hill3(input, alphabet, key, decrypt, policy, step);
        else if (is_playfair) output = crypto::classic::playfair(input, key, decrypt, step);
        else if (is_grille) output = crypto::classic::grille(input, alphabet, key, decrypt, step);
        else output = crypto::classic::caesar(input, alphabet, shift, decrypt, policy, step);
        const auto encoded = crypto::core::encode_utf8(output);
        const auto chart = chart_path.empty() ? std::string{} : crypto::viz::frequency_svg(
            input, output, alphabet, "файл=" + input_path + "; метод=" + argv[1] + "; абетка=" + alphabet_name +
            (uses_key_file ? "; ключ=окремий файл" : "; зсув=" + std::to_string(shift)) +
            "; операція=" + (decrypt ? "decrypt" : "encrypt"));
        if (!chart_path.empty()) crypto::core::write_atomic(chart_path, chart);
        if (!trace_path.empty()) crypto::core::write_atomic(trace_path, steps.str());
        crypto::core::write_atomic(output_path, encoded);
        if (trace && trace_path.empty()) std::cout << steps.str();
        std::cout << "Готово: " << output.size() << " кодових точок, " << encoded.size() << " байтів UTF-8.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Помилка: " << error.what() << '\n';
        return 1;
    }
}
