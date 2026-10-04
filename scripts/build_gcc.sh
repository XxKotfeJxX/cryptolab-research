#!/usr/bin/env sh
set -eu
mkdir -p build
c++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -O2 -Isrc src/core/utf8.cpp src/core/alphabet.cpp src/core/hex.cpp src/core/files.cpp src/core/sha256.cpp src/core/otp.cpp src/classic/caesar.cpp src/classic/substitution.cpp src/classic/vigenere.cpp src/classic/hill.cpp src/classic/feistel_demo.cpp src/classic/playfair.cpp src/classic/grille.cpp src/viz/svg.cpp src/app/main.cpp -o build/cryptolab
c++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -O2 -Isrc src/core/utf8.cpp src/core/alphabet.cpp src/core/hex.cpp src/core/files.cpp src/core/sha256.cpp src/core/otp.cpp src/classic/caesar.cpp src/classic/substitution.cpp src/classic/vigenere.cpp src/classic/hill.cpp src/classic/feistel_demo.cpp src/classic/playfair.cpp src/classic/grille.cpp src/viz/svg.cpp tests/test_main.cpp -o build/tests
