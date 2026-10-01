#include "classic/caesar.hpp"
#include "core/alphabet.hpp"
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
        const auto svg = crypto::viz::frequency_svg(U"ABBA", U"DEED", en);
        expect(svg.find("<svg") != std::string::npos && svg.find("Вхід: 4 літер") != std::string::npos, "svg counts");
        std::cout << "OK: UTF-8, two alphabets, Caesar vectors, edge cases, trace, SVG\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n'; return 1;
    }
}
