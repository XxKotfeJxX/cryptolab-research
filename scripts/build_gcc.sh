#!/usr/bin/env sh
set -eu
mkdir -p build
c++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -O2 -Isrc src/core/utf8.cpp src/core/alphabet.cpp src/classic/caesar.cpp src/viz/svg.cpp src/app/main.cpp -o build/cryptolab
c++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -O2 -Isrc src/core/utf8.cpp src/core/alphabet.cpp src/classic/caesar.cpp src/viz/svg.cpp tests/test_main.cpp -o build/tests
