#!/bin/sh
find . -type f \( -iname "*.c" -o -iname "*.cpp" -o -iname "*.cc" -o -iname "*.cxx" -o -iname "*.h" -o -iname "*.hpp" -o -iname "*.hh" -o -iname "*.hxx" \) -print0 | xargs -0 -r clang-format -i -style=file
