$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path build -Force | Out-Null
$common = @(
    '-std=c++20', '-Wall', '-Wextra', '-Wpedantic', '-Werror', '-O2', '-Isrc',
    'src/core/utf8.cpp', 'src/core/alphabet.cpp', 'src/core/hex.cpp',
    'src/core/files.cpp', 'src/core/sha256.cpp', 'src/core/otp.cpp', 'src/classic/caesar.cpp',
    'src/classic/substitution.cpp', 'src/classic/vigenere.cpp',
    'src/classic/hill.cpp', 'src/classic/feistel_demo.cpp',
    'src/classic/playfair.cpp', 'src/classic/grille.cpp',
    'src/classic/homophonic.cpp', 'src/viz/svg.cpp'
)
& g++ @common 'src/app/main.cpp' '-o' 'build/cryptolab.exe'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& g++ @common 'tests/test_main.cpp' '-o' 'build/tests.exe'
exit $LASTEXITCODE
