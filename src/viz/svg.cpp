#include "viz/svg.hpp"
#include "core/utf8.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <vector>

namespace crypto::viz {
std::string frequency_svg(std::u32string_view before, std::u32string_view after,
                          const core::Alphabet& alphabet) {
    const auto n = alphabet.upper.size();
    std::vector<std::size_t> left(n), right(n);
    std::size_t left_total = 0, right_total = 0;
    for (auto cp : before) { auto i = alphabet.index(cp); if (i != core::not_found) { ++left[i]; ++left_total; } }
    for (auto cp : after) { auto i = alphabet.index(cp); if (i != core::not_found) { ++right[i]; ++right_total; } }
    const auto width = 100 + 28 * n;
    const int height = 380;
    double maximum = 0;
    for (std::size_t i = 0; i < n; ++i) {
        if (left_total) maximum = std::max(maximum, 100.0 * left[i] / left_total);
        if (right_total) maximum = std::max(maximum, 100.0 * right[i] / right_total);
    }
    if (maximum == 0) maximum = 1;
    std::ostringstream out;
    out << std::fixed << std::setprecision(2);
    out << "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"" << width << "\" height=\"" << height
        << "\" viewBox=\"0 0 " << width << ' ' << height << "\">\n"
        << "<rect width=\"100%\" height=\"100%\" fill=\"#fff\"/>\n"
        << "<text x=\"52\" y=\"28\" font-size=\"16\" fill=\"#111\">Частка кожної літери, %</text>\n"
        << "<rect x=\"52\" y=\"43\" width=\"12\" height=\"12\" fill=\"#277da1\"/>"
        << "<text x=\"70\" y=\"54\" font-size=\"12\">Вхід</text>"
        << "<rect x=\"125\" y=\"43\" width=\"12\" height=\"12\" fill=\"#f3722c\"/>"
        << "<text x=\"143\" y=\"54\" font-size=\"12\">Вихід</text>\n"
        << "<line x1=\"45\" y1=\"315\" x2=\"" << width-20 << "\" y2=\"315\" stroke=\"#444\"/>\n";
    for (std::size_t i = 0; i < n; ++i) {
        const auto x = 53 + i * 28;
        const double l = left_total ? 100.0 * left[i] / left_total : 0;
        const double r = right_total ? 100.0 * right[i] / right_total : 0;
        const double hl = l / maximum * 220, hr = r / maximum * 220;
        out << "<rect x=\"" << x << "\" y=\"" << 315-hl << "\" width=\"10\" height=\"" << hl << "\" fill=\"#277da1\"/>\n"
            << "<rect x=\"" << x+11 << "\" y=\"" << 315-hr << "\" width=\"10\" height=\"" << hr << "\" fill=\"#f3722c\"/>\n"
            << "<text x=\"" << x+10 << "\" y=\"335\" text-anchor=\"middle\" font-size=\"12\">"
            << core::encode_utf8(std::u32string(1, alphabet.upper[i])) << "</text>\n";
    }
    out << "<text x=\"52\" y=\"365\" font-size=\"12\" fill=\"#555\">Вхід: " << left_total
        << " літер; вихід: " << right_total << " літер; висота нормована за максимумом</text>\n</svg>\n";
    return out.str();
}
}
