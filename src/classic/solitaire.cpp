#include "classic/solitaire.hpp"
#include <algorithm>
#include <cstddef>
#include <numeric>
#include <stdexcept>
#include <vector>

namespace crypto::classic {
namespace {
char32_t upper_ascii(char32_t cp) {
    if (cp >= U'a' && cp <= U'z') cp -= U'a' - U'A';
    if (cp < U'A' || cp > U'Z') throw std::invalid_argument("Solitaire приймає лише ASCII A–Z");
    return cp;
}
class Deck {
    std::vector<int> cards_;
    static int value(int card) { return card > 52 ? 53 : card; }
    void move_joker(int joker) {
        const auto it = std::find(cards_.begin(), cards_.end(), joker);
        const auto position = static_cast<std::size_t>(it - cards_.begin());
        cards_.erase(it);
        cards_.insert(cards_.begin() + static_cast<std::ptrdiff_t>(position == 53 ? 1 : position + 1), joker);
    }
    void triple_cut() {
        const auto a = static_cast<std::size_t>(std::find(cards_.begin(), cards_.end(), 53) - cards_.begin());
        const auto b = static_cast<std::size_t>(std::find(cards_.begin(), cards_.end(), 54) - cards_.begin());
        const auto first = std::min(a, b), last = std::max(a, b);
        std::vector<int> cut;
        cut.reserve(54);
        cut.insert(cut.end(), cards_.begin() + static_cast<std::ptrdiff_t>(last + 1), cards_.end());
        cut.insert(cut.end(), cards_.begin() + static_cast<std::ptrdiff_t>(first),
                   cards_.begin() + static_cast<std::ptrdiff_t>(last + 1));
        cut.insert(cut.end(), cards_.begin(), cards_.begin() + static_cast<std::ptrdiff_t>(first));
        cards_.swap(cut);
    }
public:
    Deck() : cards_(54) { std::iota(cards_.begin(), cards_.end(), 1); }
    void count_cut(int count) {
        if (count == 53) return;
        std::vector<int> cut;
        cut.reserve(54);
        cut.insert(cut.end(), cards_.begin() + count, cards_.end() - 1);
        cut.insert(cut.end(), cards_.begin(), cards_.begin() + count);
        cut.push_back(cards_.back());
        cards_.swap(cut);
    }
    void shuffle_step() {
        move_joker(53);
        move_joker(54);
        move_joker(54);
        triple_cut();
        count_cut(value(cards_.back()));
    }
    void key(char32_t cp) {
        shuffle_step();
        count_cut(static_cast<int>(cp - U'A' + 1));
    }
    int next() {
        for (;;) {
            shuffle_step();
            const int card = cards_[static_cast<std::size_t>(value(cards_.front()))];
            if (card <= 52) return (card - 1) % 26 + 1;
        }
    }
};
}

std::u32string solitaire(std::u32string_view input, std::u32string_view passphrase,
                         bool decrypt, const StepCallback& step) {
    Deck deck;
    for (char32_t cp : passphrase) deck.key(upper_ascii(cp));
    std::u32string normalized;
    normalized.reserve(input.size());
    for (char32_t cp : input) normalized.push_back(upper_ascii(cp));
    std::u32string output;
    output.reserve(normalized.size());
    for (std::size_t i = 0; i < normalized.size(); ++i) {
        const int value = static_cast<int>(normalized[i] - U'A' + 1);
        const int stream = deck.next();
        const int result = decrypt ? (value - stream - 1 + 26) % 26 + 1 : (value + stream - 1) % 26 + 1;
        const char32_t cp = U'A' + result - 1;
        output.push_back(cp);
        if (step) step({i, static_cast<std::size_t>(value - 1), static_cast<std::size_t>(result - 1),
                        normalized[i], cp});
    }
    return output;
}
}
