@echo off
setlocal
if not exist build mkdir build
cl /nologo /std:c++20 /EHsc /W4 /WX /O2 /utf-8 /Isrc src\core\utf8.cpp src\core\alphabet.cpp src\core\hex.cpp src\core\files.cpp src\core\sha256.cpp src\classic\caesar.cpp src\classic\substitution.cpp src\classic\vigenere.cpp src\classic\hill.cpp src\viz\svg.cpp src\app\main.cpp /Febuild\cryptolab.exe /Fobuild\
if errorlevel 1 exit /b %errorlevel%
cl /nologo /std:c++20 /EHsc /W4 /WX /O2 /utf-8 /Isrc src\core\utf8.cpp src\core\alphabet.cpp src\core\hex.cpp src\core\files.cpp src\core\sha256.cpp src\classic\caesar.cpp src\classic\substitution.cpp src\classic\vigenere.cpp src\classic\hill.cpp src\viz\svg.cpp tests\test_main.cpp /Febuild\tests.exe /Fobuild\
exit /b %errorlevel%
