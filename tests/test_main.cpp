#include "classic/caesar.hpp"
#include "classic/feistel_demo.hpp"
#include "classic/hill.hpp"
#include "classic/playfair.hpp"
#include "classic/substitution.hpp"
#include "classic/vigenere.hpp"
#include "core/alphabet.hpp"
#include "core/error.hpp"
#include "core/files.hpp"
#include "core/hex.hpp"
#include "core/otp.hpp"
#include "core/sha256.hpp"
#include "core/utf8.hpp"
#include "viz/svg.hpp"
#include <climits>
#include <iostream>
#include <stdexcept>

using crypto::classic::InputPolicy;

template<class F> void must_reject(F function) {
    try { function(); } catch (const std::invalid_argument&) { return; }
    throw std::runtime_error("Очікували помилку входу");
}
void expect(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
int main() {
    try {
        const auto& en = crypto::core::alphabet_en();
        const auto& uk = crypto::core::alphabet_uk();
        expect(en.upper.size() == 26 && uk.upper.size() == 33, "alphabet size");
        expect(crypto::core::decode_utf8(crypto::core::encode_utf8(U"Її Ґґ 😀")) == U"Її Ґґ 😀", "utf8 roundtrip");
        must_reject([] { crypto::core::decode_utf8("\xC0\xAF"); });
        must_reject([] { crypto::core::decode_utf8("\xED\xA0\x80"); });
        must_reject([] { crypto::core::decode_utf8("\xF4\x90\x80\x80"); });
        must_reject([] { crypto::core::decode_utf8("\xE2\x82"); });
        const auto hex_bytes = crypto::core::decode_hex("00aFff");
        expect(hex_bytes.size() == 3 && hex_bytes[0] == 0 && hex_bytes[1] == 0xaf && hex_bytes[2] == 0xff, "hex decode");
        expect(crypto::core::encode_hex(hex_bytes) == "00afff", "hex encode");
        must_reject([] { crypto::core::decode_hex("0"); });
        must_reject([] { crypto::core::decode_hex("00 1f"); });
        expect(crypto::core::otp_xor(std::string("\x00\xff", 2), std::string("\xff\x55", 2)) ==
               std::string("\xff\xaa", 2), "OTP byte XOR");
        expect(crypto::core::otp_xor("", "").empty(), "OTP empty");
        must_reject([] { crypto::core::otp_xor("a", ""); });
        const std::string feistel_plain("\x12\x34", 2), feistel_key("\x01\x02\x03\x04", 4);
        expect(crypto::classic::feistel_demo(feistel_plain, feistel_key, false) ==
               std::string("\xf9\x37", 2), "independent Feistel demo vector");
        expect(crypto::classic::feistel_demo(std::string("\xf9\x37", 2), feistel_key, true) ==
               feistel_plain, "Feistel inverse");
        must_reject([&] { crypto::classic::feistel_demo("x", feistel_key, false); });
        must_reject([] { crypto::classic::feistel_demo("", "123", false); });
        try {
            crypto::core::decode_hex("gg");
            throw std::runtime_error("missing typed hex error");
        } catch (const crypto::core::InputError& error) {
            expect(error.code() == crypto::core::ErrorCode::invalid_hex, "typed hex error");
        }
        const auto digest_abc = crypto::core::sha256("abc");
        expect(crypto::core::encode_hex(digest_abc) ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "NIST SHA-256 abc");
        const auto digest_two = crypto::core::sha256(
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        expect(crypto::core::encode_hex(digest_two) ==
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "NIST SHA-256 two blocks");
        expect(crypto::classic::caesar(U"ATTACKATDAWN", en, 3, false, InputPolicy::strict) == U"DWWDFNDWGDZQ", "en example");
        expect(crypto::classic::caesar(U"DWWDFNDWGDZQ", en, 3, true, InputPolicy::strict) == U"ATTACKATDAWN", "en inverse");
        expect(crypto::classic::caesar(U"АБВГҐ", uk, 3, false, InputPolicy::strict) == U"ГҐДЕЄ", "uk order");
        expect(crypto::classic::caesar(U"ЬЮЯ", uk, 1, false, InputPolicy::strict) == U"ЮЯА", "uk wrap");
        expect(crypto::classic::caesar(U"a z!", en, 1, false, InputPolicy::passthrough) == U"B A!", "passthrough");
        expect(crypto::classic::caesar(U"A", en, LLONG_MIN, true, InputPolicy::strict) ==
               crypto::classic::caesar(U"A", en, -(LLONG_MIN % 26), false, InputPolicy::strict), "min integer");
        must_reject([&] { crypto::classic::caesar(U"A!", en, 3, false, InputPolicy::strict); });
        int calls = 0;
        crypto::classic::caesar(U"A?B", en, 3, false, InputPolicy::passthrough,
            [&](const crypto::classic::Step& s) { ++calls; expect(s.output_index == s.input_index + 3, "trace index"); });
        expect(calls == 2, "trace count");
        const std::u32string published_key = U"mnbvcxzasdfghjklpoiuytrewq";
        const auto published_cipher = crypto::classic::substitution(
            U"bob. i love you. alice", en, published_key, false, InputPolicy::passthrough);
        expect(published_cipher == U"NKN. S GKTC WKY. MGSBC", "CMU substitution vector");
        expect(crypto::classic::substitution(published_cipher, en, published_key, true, InputPolicy::passthrough) ==
               U"BOB. I LOVE YOU. ALICE", "substitution decrypt");
        std::u32string uk_key(uk.upper.rbegin(), uk.upper.rend());
        expect(crypto::classic::substitution(
                   crypto::classic::substitution(U"АБВ", uk, uk_key, false, InputPolicy::strict),
                   uk, uk_key, true, InputPolicy::strict) == U"АБВ", "uk substitution inverse");
        must_reject([&] { crypto::classic::substitution(U"А", uk, U"АБВ", false, InputPolicy::strict); });
        must_reject([&] { crypto::classic::substitution(U"A", en, U"AAAAAAAAAAAAAAAAAAAAAAAAAA", false, InputPolicy::strict); });
        must_reject([&] { crypto::classic::substitution(U"A!", en, published_key, false, InputPolicy::strict); });
        expect(crypto::classic::vigenere(U"ATTACKATDAWN", en, U"DECAF", false, InputPolicy::strict) ==
               U"DXVAHNEVDFZR", "CMU Vigenere vector");
        expect(crypto::classic::vigenere(U"DXVAHNEVDFZR", en, U"DECAF", true, InputPolicy::strict) ==
               U"ATTACKATDAWN", "Vigenere decrypt");
        expect(crypto::classic::vigenere(U"A!A", en, U"BC", false, InputPolicy::passthrough) ==
               U"B!C", "Vigenere skips punctuation");
        expect(crypto::classic::vigenere(U"АБВ", uk, U"Ґ", false, InputPolicy::strict) == U"ҐДЕ",
               "uk Vigenere order");
        must_reject([&] { crypto::classic::vigenere(U"A", en, U"", false, InputPolicy::strict); });
        must_reject([&] { crypto::classic::vigenere(U"A", en, U"B!", false, InputPolicy::strict); });
        expect(crypto::classic::hill3(U"ACT", en, U"GYBNQKURP", false, InputPolicy::strict) == U"POH",
               "FSU Hill vector");
        expect(crypto::classic::hill3(U"POH", en, U"GYBNQKURP", true, InputPolicy::strict) == U"ACT",
               "Hill inverse");
        expect(crypto::classic::hill3(U"A!CT", en, U"GYBNQKURP", false, InputPolicy::passthrough) == U"P!OH",
               "Hill passthrough block positions");
        expect(crypto::classic::hill3(U"АБВ", uk, U"БАААБАААБ", false, InputPolicy::strict) == U"АБВ",
               "uk Hill identity");
        expect(crypto::classic::hill3(U"БҐҐ", uk, U"ВБААВБААВ", true, InputPolicy::strict) == U"АБВ",
               "uk Hill inverse nontrivial");
        must_reject([&] { crypto::classic::hill3(U"AC", en, U"GYBNQKURP", false, InputPolicy::strict); });
        must_reject([&] { crypto::classic::hill3(U"ACT", en, U"AAAAAAAAA", false, InputPolicy::strict); });
        must_reject([&] { crypto::classic::hill3(U"ACT", en, U"GYBNQKUR", false, InputPolicy::strict); });
        expect(crypto::classic::playfair(U"HIDETHEGOLDINTHETREESTUMP", U"PLAYFAIREXAMPLE", false) ==
               U"BMODZBXDNABEKUDMUIXMMOUVIF", "published Playfair vector");
        expect(crypto::classic::playfair(U"BMODZBXDNABEKUDMUIXMMOUVIF", U"PLAYFAIREXAMPLE", true) ==
               U"HIDETHEGOLDINTHETREXESTUMP", "Playfair prepared plaintext");
        expect(crypto::classic::playfair(U"XX", U"MONARCHY", false).size() == 4, "Playfair repeat-X filler");
        must_reject([] { crypto::classic::playfair(U"ABC", U"MONARCHY", true); });
        must_reject([] { crypto::classic::playfair(U"A!", U"MONARCHY", false); });
        must_reject([] { crypto::classic::playfair(U"AB", U"", false); });
        const auto svg = crypto::viz::frequency_svg(U"ABBA", U"DEED", en);
        expect(svg.find("<svg") != std::string::npos && svg.find("Вхід: 4 літер") != std::string::npos, "svg counts");
        expect(crypto::viz::frequency_svg(U"A", U"B", en, "a&b<file").find("a&amp;b&lt;file") != std::string::npos,
               "svg metadata escaping");
        std::cout << "OK: UTF-8, hex, NIST SHA-256, alphabets, Caesar, substitution, Vigenere, Hill, SVG\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n'; return 1;
    }
}
