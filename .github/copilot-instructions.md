# GitHub Copilot Project Instructions

You are assisting with a modern C++17 codebase that follows the **Applied Informatics C++ Coding Style Guide v1.5**, with the following **project-specific rules and conventions**:

## 💡 General Coding Guidelines

- Use **C++17** features where appropriate:
  - `auto`
  - `std::optional`
  - `if constexpr`
  - `structured bindings`
  - etc.

- Code must be clean, modular, and production-grade.
- All generated code must be **original** — do not copy from public repositories, documentation, or third-party code examples.

## 🧱 Formatting and Style Rules

- Use **2-space indentation** (no tabs).
- Use **Allman brace style**:
  - Place the opening `{` on its own line, aligned with its construct (function, class, loop, if, etc.).
- **Always** use braces `{}` around control blocks (`if`, `else`, `for`, `while`, `do`) — even for single statements.
- Use `#pragma once` in header files (instead of include guards).
- Use `.hpp` for **header-only classes** (e.g. templates, inline utilities).
- Every non-header-only class must have a `.h` and `.cpp` file pair. One class per file.


## 🔤 Naming Conventions

- Use **camelCase** for functions and variables.
- Use **PascalCase** for class, struct, and enum names.
- Prefix **private/protected** member variables with a single underscore (`_`).
- Constants and enum values should use `ALL_UPPERCASE_WITH_UNDERSCORES`.

## 🧼 Memory and Safety

- Avoid global variables.
- Never use raw `new` or `delete`.
- Always use smart pointers (`std::unique_ptr`, `std::shared_ptr`) and **RAII** for resource management.
- Destructors must never throw. Use `try`/`catch (...)` with `poco_unexpected()` for error signaling.

## 🔍 Namespace and Includes

- **Do not use** `using namespace` — especially not in header files.
- Always fully qualify names from the standard library (e.g., `std::string`).
- Use `#include "ClassName.h"` for local headers, and angle brackets `<...>` for system includes.
- Never use relative paths like `../` in includes.

## 🧾 Documentation

- Use `///` **Doxygen-style comments** for:
  - Public classes
  - Public functions
  - Enums and typedefs
- All source files must begin with a file header including:
  - Filename
  - Module/package name
  - License information (if applicable)

## 🧩 Project Layout

- `include/` — Public headers (organized in subdirectories like `sip/`, `portal/`, `routing/`, etc.)
- `src/` — Implementation files (`.cpp`)
- `tests/` — Unit tests (Catch2)
- `tests/sip/`, `tests/portal/` — Organized per subsystem

## 🚫 Code Reuse Restriction

> **IMPORTANT**: Do not copy/paste code from open-source repositories, online documentation, or third-party sources. All code must be clean-room, model-generated, and license-safe.

---

By following these guidelines, Copilot should assist in generating consistent, idiomatic, and maintainable code throughout the project.