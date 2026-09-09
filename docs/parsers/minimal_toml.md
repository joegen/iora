# Iora Minimal TOML parser & serializer — Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-09 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/parsers/minimal_toml.hpp` |
| **Namespace** | `iora::parsers::toml` |
| **Dependencies** | Standard library only — `<algorithm>`, `<cstdint>`, `<fstream>`, `<iomanip>`, `<memory>`, `<optional>`, `<sstream>`, `<stdexcept>`, `<string>`, `<unordered_map>`, `<variant>`, `<vector>`. No external libraries. |

---

## 2. Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-09-09 | Initial guide for the implemented header-only minimal TOML parser/serializer (`iora::parsers::toml`), including the array-of-tables support (trackers 2026-04-19-4 through 2026-04-19-7). |

---

## 3. Executive Summary

### Problem

Iora is a self-contained C++17 microservice framework with a stated design goal of **zero external dependencies**. Configuration, however, is naturally expressed in TOML: `iora::core::ConfigLoader` (a downstream consumer, documented separately) needs to read service configuration files with sections, nested tables, and repeated `[[array-of-tables]]` blocks. Pulling in a full third-party TOML library (for example `toml++`) to satisfy that need would violate the zero-dependency principle and drag in a large amount of surface area — full TOML v1.0 date/time types, inline tables, multi-line strings, integer bases — that Iora's configuration files never use.

The alternative — scattering ad-hoc string splitting and `std::stoi` calls across each consumer — produces fragile, duplicated, and inconsistent parsing logic.

### Solution

A single header, `include/iora/parsers/minimal_toml.hpp`, providing a **deliberately minimal** recursive-descent TOML reader and writer built entirely on the standard library:

- **`iora::parsers::toml::table`, `array`, `node`** — a lightweight document object model. `value_type` is a `std::variant` over the scalar and container alternatives; nested tables and arrays are held by `std::shared_ptr`.
- **`iora::parsers::toml::parser`** plus the free functions `parse(const std::string&)` and `parse_file(const std::string&)` — a single-pass, character-at-a-time recursive-descent parser that returns a root `table`.
- **`iora::parsers::toml::serializer`** — a static-method writer that emits a `table` back to TOML text, including `[[array-of-tables]]` reconstruction, with `serialize()` and `write_file()`.
- **A supported subset that is intentionally narrow** — bare keys, `[section]` and dotted `[a.b]` headers, `[[array-of-tables]]`, `#` comments, and five value kinds (string, integer, float, boolean, and array — the first four scalar, plus arrays). Everything the subset omits is enumerated in [Section 12](#12-known-limitations).

### Technical Impact

- **Zero external dependencies** — the entire parser and serializer are header-only standard C++17; nothing links against a third-party TOML library.
- **Single-pass parse**, O(n) in the input length, with no separate tokenizer stage — the parser reads characters directly from the input string.
- **O(1) average key lookup** — each `table` is backed by `std::unordered_map<std::string, node>`.
- **Shared-pointer DOM** — nested tables and arrays are reference-counted, so subtrees can be aliased cheaply, at the cost of the aliasing caveat described in [Section 8](#8-thread-safety-model).
- **Deterministic serialization** — the serializer sorts keys within each scope, so a table round-trips to stable, diff-friendly output.

---

## 4. System Architecture

### Component Relationships

The header defines three data classes, one parser class, one serializer class, and three free functions. Ownership of nested structure flows through `std::shared_ptr`:

```
iora::parsers::toml
│
├── value_type  =  std::variant< std::monostate,        // empty / absent
│                                int64_t,                // integer
│                                double,                 // float
│                                bool,                   // boolean
│                                std::string,            // string
│                                std::shared_ptr<table>, // sub-table
│                                std::shared_ptr<array> >// array
│
├── class node          // wraps a single value_type
│     └── _value : value_type
│
├── class array         // ordered sequence of value_type
│     └── _values : std::vector<value_type>
│
├── class table         // string-keyed map of nodes  (the document root)
│     └── _values : std::unordered_map<std::string, node>
│           └── each node may own a shared_ptr<table> or shared_ptr<array>
│                 → forming the nested document tree
│
├── class parser        // recursive-descent reader; produces a `table`
│     ├── _input : std::string   (owned copy of the source text)
│     └── _pos   : size_t        (current read offset)
│
├── class serializer    // static-only writer; consumes a `table`
│     (no instance state)
│
└── free functions
      ├── parse(const std::string& tomlString) -> table
      └── parse_file(const std::string& filename) -> table
```

There is no base class, no virtual dispatch, and no global or static mutable state. A `parser` owns a private copy of its input string and a cursor; a `serializer` is a bag of static methods with no state at all.

### Data Flow: parsing a document

```mermaid
sequenceDiagram
    participant App as Caller
    participant Free as toml::parse
    participant P as parser
    participant Root as root table
    participant Sub as sub-table / array

    App->>Free: parse(tomlString)
    Free->>P: parser(tomlString)
    Free->>P: parse()
    loop until end of input
        P->>P: skipWhitespaceAndComments()
        alt line starts with '[['
            P->>P: parseArraySection()
            P->>Sub: ensureArrayTable(root, path)
            Note over P,Sub: append a new shared_ptr<table><br/>to the array; retarget cursor
        else line starts with '['
            P->>P: parseSection()
            P->>Sub: ensureTable(root, path)
            Note over P,Sub: create/descend dotted path;<br/>retarget cursor
        else key = value line
            P->>P: parseKeyValue()
            P->>P: parseValue() (string/number/bool/array)
            P->>Root: currentTable->insert(key, node)
        end
    end
    P-->>Free: root table (by value)
    Free-->>App: table
```

### Threading Model

| Thread | Responsibility |
|--------|----------------|
| Caller thread | Constructs `parser` / calls `toml::parse` / `toml::parse_file`, and consumes the returned `table`. All parsing runs synchronously on this thread. |
| (none) | The parser and serializer spawn no threads, register no callbacks, and touch no shared global state. |

Concurrency is entirely the caller's concern; see [Section 8](#8-thread-safety-model).

---

## 5. Component Deep Dive

### 5.1 The document model: `value_type`, `node`, `array`, `table`

**`value_type`** is the discriminated union at the center of the model:

```cpp
using value_type = std::variant<std::monostate, int64_t, double, bool, std::string,
                                std::shared_ptr<table>, std::shared_ptr<array>>;
```

`std::monostate` is the "no value" alternative — a default-constructed `node` holds it, and it is the sentinel returned when a lookup misses (see `at_path` below). Scalars are stored by value; containers are stored by `std::shared_ptr`, so a `node` is cheap to copy and subtrees can be shared.

**`node`** wraps exactly one `value_type` and exposes type predicates and typed extraction:

- Predicates: `is_value()`, `is_string()`, `is_integer()`, `is_floating_point()`, `is_boolean()`, `is_array()`, `is_table()`. `is_value()` is true for anything that is not `std::monostate`.
- `explicit operator bool()` mirrors `is_value()` — a node converts to `true` iff it holds a real value.
- Typed extraction, `template <typename T> std::optional<T> as() const`, is specialized by `if constexpr`:
  - `as<int64_t>()` — succeeds only on the integer alternative.
  - `as<double>()` — succeeds on the float alternative **and** widens an integer to `double` (an `int64_t` value is returned as `static_cast<double>`).
  - `as<bool>()` — succeeds only on the boolean alternative.
  - `as<std::string>()` — succeeds only on the string alternative.
  - Any other `T`, or a type mismatch, returns `std::nullopt`.
- `value<T>()` is a thin alias that forwards to `as<T>()`.
- Container access: `as_array()` and `as_table()` (both `const` and non-`const` overloads) return a raw pointer to the pointed-to `array` / `table`, or `nullptr` if the node does not hold that alternative. The returned pointer is owned by the node's internal `shared_ptr` and is valid only while that node (or a copy sharing ownership) is alive.
- `get_value()` returns a reference to the underlying `value_type` for callers that want to inspect the variant directly.

**Note on `as<double>()` asymmetry:** the integer-to-double widening is one-directional. `as<int64_t>()` will *not* extract from a node holding a `double`; only `as<double>()` accepts an integer. This is source-verified behavior, not an oversight to route around.

**`array`** is a thin wrapper over `std::vector<value_type>`:

- `push_back` (const-ref and rvalue overloads), `size()`, `empty()`.
- `begin()`/`end()` (mutable and const) for range iteration.
- `operator[](size_t)` (mutable and const) — **unchecked**; it forwards to `std::vector::operator[]` and performs no bounds checking.

**`table`** is a thin wrapper over `std::unordered_map<std::string, node>`:

- `contains(key)`, `empty()`, `size()`.
- `operator[](const std::string&)` — **inserts** a default `node` if the key is absent (standard `unordered_map` semantics).
- `at(const std::string&) const` — throws `std::out_of_range` (`"Key not found: " + key`) if the key is absent.
- `insert(key, node)` (const-ref and rvalue overloads) — assigns, overwriting any existing value at that key.
- `begin()`/`end()` (mutable and const) for range iteration. Iteration order is **unspecified** — it is `unordered_map` order, not declaration order.
- `at_path(const std::string& dottedPath) const` — splits the path on `.` and walks the tree. Each intermediate segment must resolve to a sub-table (via `as_table()`); the terminal segment's node is returned **by value**. A missing key, a non-table intermediate, or an empty path all return a default (monostate) `node`. Note that `at_path` returns a copy, whereas `at` returns a reference.

### 5.2 The parser: recursive descent over a character cursor

`parser` holds an owned copy of the input (`std::string _input`) and a read offset (`size_t _pos`). All reading goes through four primitives:

```cpp
bool isEnd() const { return _pos >= _input.size(); }
char peek() const { return isEnd() ? '\0' : _input[_pos]; }
char peek(size_t offset) const;   // lookahead; '\0' past the end
char advance() { return isEnd() ? '\0' : _input[_pos++]; }
```

`'\0'` doubles as the end-of-input sentinel returned by `peek`/`advance`, which is why several guards test `peek() != '\0'` explicitly.

**Whitespace and comments.** Three skip helpers with distinct behavior:

- `skipWhitespace()` — consumes spaces/tabs but **stops at `\n`** (used inside a single logical line, e.g. around `=`).
- `skipWhitespaceAndNewlines()` — consumes all `std::isspace` characters including newlines.
- `skipWhitespaceAndComments()` — repeatedly skips whitespace/newlines, then if it sees `#`, consumes to end of line, and loops. This is the top-level between-item skip and is what makes both full-line and trailing `#` comments work.

**Top-level loop (`parse()`).** After skipping whitespace/comments, the parser dispatches on the first character:

- `[[` → `parseArraySection()` then `ensureArrayTable()` — an array-of-tables header; the current insertion target becomes the newly appended element table.
- `[` → `parseSection()` then `ensureTable()` — a standard section header; the current insertion target becomes that (possibly nested) table.
- anything else → `parseKeyValue()`; a non-empty key is inserted via `currentTable->insert(key, value)`, while an empty key (a line beginning with a non-key character) is rejected with `std::runtime_error` -- this is what stops the top-level loop from stalling on a non-progress line.

**`parseSection()`** consumes the opening `[`, then accumulates characters until `]`, rejecting `\n`, `\r`, and `\0` inside the header (each raises `std::runtime_error("Unterminated [section] header")`). It **does not** strip surrounding whitespace — `[ a.b ]` yields the literal section string `" a.b "`, which then splits into keys `" a"` and `"b "` (spaces included). This is a deliberate, source-commented divergence from the array-of-tables path.

**`parseArraySection()`** consumes both `[` characters, accumulates until the first `]` (again rejecting `\n`/`\r`/`\0`), then requires a second `]`. Unlike `parseSection`, it **strips** surrounding ASCII spaces and tabs from the header — `[[ a.b ]]` yields `"a.b"`. An all-whitespace header yields the empty string.

**`ensureTable(root, path)`** splits `path` on `.` and descends, creating any missing intermediate tables (`node(std::make_shared<table>())`). If a path segment already exists but is not a table, it throws — with a specific message for the array-of-tables collision (`"Cannot redeclare [[...]] as [...]"`) and a generic `"Invalid table path"` otherwise.

**`ensureArrayTable(root, dottedPath)`** resolves the parent path via `ensureTable` (for a dotted path) then, at the terminal key, ensures an `array` exists, appends a fresh `std::make_shared<table>()`, and returns that new element as the current target. It rejects three conflicts with `std::runtime_error`:

1. Empty header (`"Empty array-of-tables header"`).
2. Terminal key already declared as a non-array (`"Cannot redeclare [...] as [[...]]"`).
3. Terminal key is a **value array** (a non-empty array whose first element is not a `shared_ptr<table>`) — `"Cannot redeclare value array"`. This guard prevents silently appending a table into an array of scalars.

**`parseKeyValue()` / `parseKey()`.** `parseKey` accumulates characters in the class `[A-Za-z0-9_\-.]` (alphanumeric plus underscore, hyphen, and dot). It then expects `=` (else `std::runtime_error("Expected '=' after key")`) and parses the value. Note that because `.` is a legal key character, a key like `a.b = 1` is stored **literally** as the single key `"a.b"` — it is *not* expanded into nested tables (see [Section 12](#12-known-limitations)).

**`parseValue()`** dispatches on the first non-space character:

- `"` or `'` → `parseString()`
- `[` → `parseArray()`
- `t` or `f` → `parseBool()`
- `+`, `-`, or a digit → `parseNumber()`
- otherwise → `std::runtime_error("Invalid value")`

**`parseString()`** records the opening quote character and reads until the matching quote. A backslash triggers escape processing: `\n`, `\t`, `\r`, `\\`, `\"`, `\'` map to their control/literal characters; any other escaped character is emitted **verbatim with the backslash dropped** (the `default` case appends `c`). Escape processing is applied to **both** double- and single-quoted strings — a single-quoted string is *not* treated as a TOML literal string. An unterminated string throws `std::runtime_error("Unterminated string")`.

**`parseArray()`** consumes `[`, then repeatedly parses values separated by optional commas, using `skipWhitespaceAndNewlines()` between elements (so arrays may span multiple lines). Each element is stored as `parseValue().get_value()`, so arrays may nest arrays and, in principle, hold mixed types. An unterminated array throws `std::runtime_error("Unterminated array")`. **Comments are not recognized inside an array literal** — the inter-element skip is whitespace/newline only.

**`parseBool()`** accumulates alphabetic characters and matches exactly `"true"` or `"false"`; anything else throws `std::runtime_error("Invalid boolean value: " + word)`.

**`parseNumber()`** accumulates an optional leading sign followed by characters in `[0-9.eE+-]`. If a `.`, `e`, or `E` is seen, the token is parsed as a `double` via `std::stod`; otherwise as `int64_t` via `std::stoll`. Malformed or out-of-range tokens propagate the exception thrown by `std::stod`/`std::stoll` (`std::invalid_argument` or `std::out_of_range`). No thousands separators, underscores, or non-decimal bases are recognized.

### 5.3 The serializer: deterministic table-to-text

`serializer` is stateless; all methods are `static`.

- `serialize(const table&) -> std::string` — the entry point; drives `serializeTable` with an empty prefix.
- `write_file(const std::string& filename, const table&)` — opens an `std::ofstream`, throwing `std::runtime_error("Cannot open file for writing: ...")` on failure, and writes `serialize()`'s result.

**`serializeTable(os, tbl, prefix)`** partitions the table's entries into three buckets:

1. `tables` — nodes holding a sub-table.
2. `arraysOfTables` — array nodes that are **non-empty and whose first element is a `shared_ptr<table>`**. This mirrors the parser's `ensureArrayTable` guard exactly.
3. `simpleValues` — everything else, including scalars, value arrays, and **empty arrays** (which therefore emit as `key = []`).

Each bucket is sorted lexicographically by key, giving stable output. A `[prefix]` header is emitted only when `prefix` is non-empty **and** there is at least one simple value to place under it (so a table that contains only sub-tables or only arrays-of-tables does not emit a spurious single-bracket header). Arrays-of-tables emit one `[[fullPrefix]]` header per element, recursing with an **empty** prefix (the header already scopes the element). Sub-tables recurse with `prefix + "." + key`.

**`serializeValue` / `serializeValueType`** render scalars: strings are quoted and escaped via `escapeString`; integers print directly; doubles print with `std::setprecision(15)`; booleans print as `true`/`false`; arrays print inline as `[a, b, c]`. If a value array element is itself a `shared_ptr<table>` (a mixed array that cannot be expressed as inline TOML), `serializeValueType` throws `std::runtime_error("minimal_toml serializer: mixed-type array contains a sub-table element ...")`.

**`escapeString`** escapes `\n`, `\t`, `\r`, `\\`, and `"`. Notably it does **not** escape `'`, and it does not emit `\uXXXX` for other control characters.

---

## 6. Usage Guide

All examples assume:

```cpp
#include "iora/parsers/minimal_toml.hpp"

namespace toml = iora::parsers::toml;
```

### Example 1: parse a string and read scalars

```cpp
void readServiceConfig()
{
  const std::string text =
    "name = \"gateway\"\n"
    "port = 8080\n"
    "timeout = 2.5\n"
    "enabled = true\n";

  toml::table root = toml::parse(text);

  std::optional<std::string> name = root.at("name").as<std::string>();
  std::optional<int64_t> port = root.at("port").as<int64_t>();
  std::optional<double> timeout = root.at("timeout").as<double>();
  std::optional<bool> enabled = root.at("enabled").as<bool>();

  if (name && port && timeout && enabled)
  {
    // use *name, *port, *timeout, *enabled
  }
}
```

### Example 2: navigate nested sections with `at_path`

```cpp
void readNested()
{
  const std::string text =
    "[server.tls]\n"
    "cert = \"/etc/iora/cert.pem\"\n"
    "verify = true\n";

  toml::table root = toml::parse(text);

  toml::node cert = root.at_path("server.tls.cert");
  if (cert.is_string())
  {
    std::string path = *cert.as<std::string>();
    // use path
  }
}
```

### Example 3: iterate an array-of-tables

```cpp
void readServers()
{
  const std::string text =
    "[[servers]]\n"
    "host = \"a.example\"\n"
    "port = 5060\n"
    "\n"
    "[[servers]]\n"
    "host = \"b.example\"\n"
    "port = 5061\n";

  toml::table root = toml::parse(text);

  toml::node servers = root.at_path("servers");
  if (servers.is_array())
  {
    const toml::array *arr = servers.as_array();
    for (const toml::value_type &elem : *arr)
    {
      if (auto *tblPtr = std::get_if<std::shared_ptr<toml::table>>(&elem))
      {
        const toml::table &row = **tblPtr;
        std::optional<std::string> host = row.at("host").as<std::string>();
        std::optional<int64_t> port = row.at("port").as<int64_t>();
        // use *host, *port
      }
    }
  }
}
```

### Example 4: build a document and serialize it

```cpp
std::string buildConfig()
{
  toml::table root;
  root.insert("name", toml::node(toml::value_type{std::string("gateway")}));
  root.insert("port", toml::node(toml::value_type{static_cast<int64_t>(8080)}));

  auto tags = std::make_shared<toml::array>();
  tags->push_back(toml::value_type{std::string("edge")});
  tags->push_back(toml::value_type{std::string("public")});
  root.insert("tags", toml::node(toml::value_type{tags}));

  return toml::serializer::serialize(root);
  // -> name = "gateway"
  //    port = 8080
  //    tags = ["edge", "public"]
}
```

### Example 5: read from a file, guarding for failure

```cpp
bool loadFrom(const std::string &path)
{
  try
  {
    toml::table root = toml::parse_file(path);
    // consume root...
    return true;
  }
  catch (const std::runtime_error &e)
  {
    // parse_file throws "Cannot open file: <path>" if the file is missing,
    // or a parse-error runtime_error for malformed content.
    return false;
  }
}
```

### Anti-Patterns

- **Do NOT** assume `table::operator[]` is read-only. `root["missing"]` **inserts** a default (monostate) node as a side effect, mutating the table. Use `contains()` / `at()` / `at_path()` to probe without inserting.
- **Do NOT** call `table::at()` or `array::operator[]` without checking presence/size first. `at()` throws `std::out_of_range` on a missing key; `array::operator[]` is unchecked and will read out of bounds.
- **Do NOT** treat a single-quoted string as a TOML literal string. This parser processes backslash escapes inside single quotes too, so `'C:\temp'` does **not** round-trip as the literal path.
- **Do NOT** write a dotted key as `a.b = 1` expecting nested tables. It is stored as the flat key `"a.b"`, and `at_path("a.b")` will *not* find it. Use a `[a]` section header with `b = 1` instead.
- **Do NOT** hold the raw pointer from `as_array()` / `as_table()` after the owning `node` (and every copy sharing its `shared_ptr`) has been destroyed — it dangles.
- Malformed top-level lines (e.g. `@foo = 1`, `=1`, a quoted key) are rejected with a parse-error `std::runtime_error`; the parser no longer stalls on a non-progress line (see [Section 12](#12-known-limitations)).

---

## 7. Call Flow / Sequence Reference

### 7.1 Success path: `parse("[a.b]\nk = 1\n")`

| Step | Method | Action | State after |
|------|--------|--------|-------------|
| 1 | `parse` | `skipWhitespaceAndComments()` at offset 0 | `_pos` at `[` |
| 2 | `parse` | `peek()=='['`, `peek(1)!='['` → `parseSection()` | reads `a.b`, consumes `]`; returns `"a.b"` |
| 3 | `ensureTable` | split `"a.b"` → `["a","b"]`; create table `a`, then table `b` under it | `currentTable` = table `b` |
| 4 | `parse` | `skipWhitespaceAndComments()` skips `\n` | `_pos` at `k` |
| 5 | `parseKeyValue` | `parseKey()` → `"k"`; expect and consume `=` | `_pos` at ` 1` |
| 6 | `parseValue` | `skipWhitespace()`, `peek()=='1'` → `parseNumber()` → `int64_t 1` | node holds `1` |
| 7 | `parse` | `currentTable->insert("k", node(1))` | `b` now has `k=1` |
| 8 | `parse` | `skipWhitespaceAndComments()`; `isEnd()` true → loop ends | — |
| 9 | `parse` | return `root` by value | `root.at_path("a.b.k")` → node holding `1` |

### 7.2 Failure path: `parse("[a.b]\nk = 1\n[[a.b]]\nx = 2\n")` (table/array collision)

| Step | Method | Action | Result |
|------|--------|--------|--------|
| 1–3 | `parse` → `ensureTable` | as above; `a.b` created as a **table** with `k=1` | table `a.b` exists |
| 4 | `parse` | next header is `[[` → `parseArraySection()` → `"a.b"` | — |
| 5 | `ensureArrayTable` | parent `a` resolved via `ensureTable`; terminal key `b` already present | — |
| 6 | `ensureArrayTable` | existing `b` node `is_array()` is false | throws `std::runtime_error("Cannot redeclare [a.b] as [[a.b]] ...")` |
| 7 | (caller) | exception propagates out of `parse` | caller's `catch` observes the error |

### 7.3 Serialization path: `serialize(root)` with a mixed array element

| Step | Method | Action | Result |
|------|--------|--------|--------|
| 1 | `serialize` | call `serializeTable(os, root, "")` | — |
| 2 | `serializeTable` | classify entries; a value-array whose first element is a scalar lands in `simpleValues` | — |
| 3 | `serializeValue` | array branch iterates elements → `serializeValueType` per element | — |
| 4 | `serializeValueType` | an element is a `shared_ptr<table>` | throws `std::runtime_error("minimal_toml serializer: mixed-type array contains a sub-table element ...")` |

---

## 8. Thread Safety Model

The parser and serializer contain **no synchronization primitives** — there are no mutexes, atomics, condition variables, or threads in the header. Thread safety is therefore a property of how the caller shares the objects.

| Operation | Synchronization | Notes |
|-----------|-----------------|-------|
| `toml::parse` / `toml::parse_file` (distinct inputs) | None needed | Each `parser` owns a private `_input` copy and `_pos`; concurrent calls on independent inputs do not interact. `parse_file` also touches only a local `std::ifstream`. |
| Concurrent reads of a shared `table` (`contains`, `at`, `at_path`, `as<>()`, iteration) | Caller-provided, if any writer exists | Const reads of a fully-built, never-mutated document from multiple threads are safe. Once any thread mutates the document, all access must be externally synchronized. |
| `table::operator[]`, `insert`, and any `push_back` / value mutation | Caller-provided | These mutate the underlying `unordered_map` / `vector`; concurrent mutation (or read during mutation) is a data race the caller must prevent. |
| `serializer::serialize` / `write_file` on a stable `table` | Caller-provided, if any writer exists | Serialization only reads the table, but a concurrent mutation of that table is a race. |
| Copying a `node` / sharing a subtree | Caller-provided | Nested tables/arrays are held by `std::shared_ptr`. Copying a `node` copies the pointer, so two `node`s can alias one `table`. `shared_ptr` control-block refcounting is atomic, **but the pointed-to `table`/`array` is not** — mutating an aliased subtree from two threads is a data race even though the `shared_ptr` copies are individually safe. |

**Recommended pattern:** parse on one thread, then publish the resulting `table` as an immutable configuration snapshot for reader threads. Do not mutate a published document in place.

---

## 9. Configuration Reference

The parser exposes no runtime-tunable parameters; behavior is fixed by the source. The values below are the hardcoded constants and behavioral defaults that affect output and parsing, listed for completeness.

| Parameter | Value | Location | Effect |
|-----------|-------|----------|--------|
| Float output precision | `std::setprecision(15)` | `serializeValue`, `serializeValueType` | Number of significant digits when serializing a `double`. |
| Integer parse type | `int64_t` via `std::stoll` | `parseNumber` | All non-float numbers parse to signed 64-bit. |
| Float parse type | `double` via `std::stod` | `parseNumber` | All float numbers parse to IEEE-754 double. |
| Bare-key character class | `[A-Za-z0-9_\-.]` | `parseKey` | Characters accepted in an unquoted key. |
| String escape set (parse) | `\n \t \r \\ \" \'` + verbatim fallthrough | `parseString` | Recognized escapes; unknown escapes drop the backslash. |
| String escape set (serialize) | `\n \t \r \\ \"` | `escapeString` | Characters escaped on output (note: `'` is not escaped). |
| Comment character | `#` (to end of line) | `skipWhitespaceAndComments` | Full-line and trailing comments outside array literals. |
| Header-forbidden characters | `\n`, `\r`, `\0` | `parseSection`, `parseArraySection` | Any of these inside a `[...]`/`[[...]]` header raises "Unterminated ...". |
| `[[...]]` header whitespace | Stripped (` ` and `\t`) | `parseArraySection` | Leading/trailing spaces/tabs removed from array-of-tables headers. |
| `[...]` header whitespace | **Not** stripped | `parseSection` | Surrounding whitespace is retained in single-bracket section names. |
| Serializer key ordering | Lexicographic (`std::sort`) | `serializeTable` | Keys within each scope are sorted for stable output. |

---

## 10. API Reference

Signatures below are transcribed exactly from the header. Namespace is `iora::parsers::toml`.

```cpp
using value_type = std::variant<std::monostate, int64_t, double, bool, std::string,
                                std::shared_ptr<table>, std::shared_ptr<array>>;

class array
{
public:
  using container_type = std::vector<value_type>;
  using iterator = container_type::iterator;
  using const_iterator = container_type::const_iterator;

  void push_back(const value_type &val);
  void push_back(value_type &&val);

  size_t size() const;
  bool empty() const;

  iterator begin();
  iterator end();
  const_iterator begin() const;
  const_iterator end() const;

  const value_type &operator[](size_t idx) const;   // unchecked
  value_type &operator[](size_t idx);                // unchecked
};

class node
{
public:
  node() = default;
  node(const value_type &val);
  node(value_type &&val);

  bool is_value() const;
  bool is_string() const;
  bool is_integer() const;
  bool is_floating_point() const;
  bool is_boolean() const;
  bool is_array() const;
  bool is_table() const;

  template <typename T> std::optional<T> as() const;     // int64_t/double/bool/string
  template <typename T> std::optional<T> value() const;  // alias for as<T>()

  array *as_array();
  const array *as_array() const;
  table *as_table();
  const table *as_table() const;

  explicit operator bool() const;

  const value_type &get_value() const;
  value_type &get_value();
};

class table
{
public:
  using container_type = std::unordered_map<std::string, node>;
  using iterator = container_type::iterator;
  using const_iterator = container_type::const_iterator;

  bool contains(const std::string &key) const;
  bool empty() const;
  size_t size() const;

  node &operator[](const std::string &key);            // inserts if absent
  const node &at(const std::string &key) const;        // throws std::out_of_range
  node at_path(const std::string &dottedPath) const;   // returns by value; monostate on miss

  iterator begin();
  iterator end();
  const_iterator begin() const;
  const_iterator end() const;

  void insert(const std::string &key, const node &value);
  void insert(const std::string &key, node &&value);
};

class parser
{
public:
  explicit parser(const std::string &input);
  table parse();   // may throw std::runtime_error
};

inline table parse_file(const std::string &filename);  // throws on open failure / parse error
inline table parse(const std::string &tomlString);     // throws std::runtime_error on parse error

class serializer
{
public:
  static std::string serialize(const table &tbl);                        // may throw std::runtime_error
  static void write_file(const std::string &filename, const table &tbl); // throws on open failure
};
```

---

## 11. Design Decisions

| Decision | Rationale |
|----------|-----------|
| Header-only, standard library only | Preserves Iora's zero-external-dependency goal; a full TOML library would violate it and add unused surface area. |
| Deliberately minimal subset | "Do not pay for what we do not use." Iora's config files use sections, dotted tables, arrays-of-tables, and five scalar kinds — nothing more. Date/time, inline tables, and integer bases are omitted by design. |
| Single-pass recursive descent, no separate lexer | Simplest correct structure for a small grammar; keeps the whole reader in one readable class and O(n) in input length. |
| `std::variant` DOM with `shared_ptr` containers | Type-safe value union; reference-counted subtrees allow cheap `node` copies and shared subtrees without manual memory management (no raw `new`/`delete`, per the coding standard). |
| Sorted serialization | Produces deterministic, diff-stable output — important for config files under version control. |
| `[[...]]` classification by "first element is a table pointer" | A single, consistent rule shared by `ensureArrayTable` (parse) and `serializeTable` (write), so parse/serialize round-trips agree on what an array-of-tables is. |
| Value-array-vs-array-of-tables collision guards throw | Redefining a key as a different type is a TOML error; throwing (rather than silently producing a malformed mixed array) surfaces the mistake at parse time. |
| `[[...]]` headers strip whitespace, `[...]` headers do not | The array-of-tables path was added later and strips per the TOML allowance for header whitespace; the single-bracket path intentionally preserved its pre-existing (non-stripping) behavior to avoid changing established parsing results. This asymmetry is source-commented. |
| `as<double>()` widens integers, but not vice versa | Configuration values written as `2` should be readable as a float where a float is expected; the reverse (truncating a float to int) would be lossy and is not offered. |
| Exceptions (`std::runtime_error` / `std::out_of_range`) for all error reporting | No error-code return channel; malformed input and missing keys are exceptional and are surfaced as throws the caller can catch. |

---

## 12. Known Limitations

The parser's name is literal: it implements a **minimal** subset of TOML. The following are unsupported or divergent, verified against `include/iora/parsers/minimal_toml.hpp`.

**Unsupported TOML features (silently absent or mis-parsed — not full TOML v1.0):**

- **Dotted keys in key/value position.** `a.b = 1` is stored as the flat key `"a.b"`, *not* as nested table `a` → `b`. `at_path("a.b")` will not find it. Nesting is only produced by `[a.b]` / `[[a.b]]` headers. (Source: `parseKey` accepts `.`; `insert` stores the literal key.)
- **Quoted keys.** `"key" = 1` is not supported; `parseKey` stops at the quote and returns an empty key, so the line is rejected with a parse error (see the note below).
- **Inline tables** — `x = { a = 1, b = 2 }`. `{` is not a recognized value start; `parseValue` throws `"Invalid value"`.
- **Date, time, and date-time types** — `1979-05-27T07:32:00Z` and friends. Such a value would enter `parseNumber` and mis-parse (e.g. `1979-05-27...` truncates at the first `-`/`.` boundaries per `stoll`/`stod`) or throw; there is no temporal type in `value_type`.
- **Integer bases and separators** — hexadecimal (`0x`), octal (`0o`), binary (`0b`), and digit-group underscores (`1_000`) are not recognized; `parseNumber` reads only `[0-9.eE+-]`.
- **Special float values** — `inf`, `nan`. `parseValue` dispatches `i`/`n` to nothing (they are not `t`/`f`/digit/sign) and throws `"Invalid value"`.
- **Multi-line basic strings** (`"""..."""`) and **multi-line literal strings** (`'''...'''`) — treated as an empty string immediately followed by more content; not handled as a single value.
- **Literal (non-escaping) strings.** Single-quoted strings are **not** literal here — `parseString` applies the same escape processing to `'...'` as to `"..."`, so `'\n'` becomes a newline rather than a two-character backslash-n.
- **Unicode escapes** — `\uXXXX` / `\UXXXXXXXX`. The `default` escape branch drops the backslash and keeps the following character verbatim (so `\u0041` becomes `u0041`), and `escapeString` never emits `\u` on output.
- **Comments inside array literals.** `parseArray` skips only whitespace/newlines between elements; a `#` inside `[...]` is not treated as a comment and will cause a parse error or be misread.
- **Duplicate-key detection.** Re-inserting the same key overwrites the previous value (last-wins via `unordered_map` / `insert`); TOML mandates this be an error. (The parser *does* detect the *type-change* collisions between `[a.b]`, `[[a.b]]`, scalars, and value arrays and throws for those.)

**Behavioral divergences / hazards:**

- **Malformed top-level lines are rejected (not silently skipped).** If a top-level line begins with a character that is neither `[`, `#`, whitespace, nor a legal bare-key character (for example `@foo = 1`, `=1`, or a quoted key `"k" = 1`), `parseKey` returns an empty key and `parse()` throws `std::runtime_error("Invalid line: expected a section header or 'key = value'")`. *(Earlier revisions returned without advancing `_pos`, so the top-level loop re-examined the same character indefinitely and the parser could fail to terminate; that infinite-loop hazard was fixed 2026-09-09. Untrusted input is now rejected rather than looping, though a caller-side size bound remains good practice.)*
- **`[...]` (single-bracket) headers retain surrounding whitespace.** `[ a.b ]` produces keys `" a"` and `"b "` (with the spaces). Only `[[...]]` headers strip whitespace. Avoid spaces inside single-bracket headers.
- **`array::operator[]` is unchecked.** Out-of-range indexing is undefined behavior; callers must consult `size()` first.
- **`table::operator[]` mutates on read-of-absent-key.** It inserts a default node, so using it to probe existence silently grows the table.
- **`as<int64_t>()` does not accept a `double` node.** Only `as<double>()` performs the integer→double widening; the reverse extraction returns `std::nullopt`.
- **Mixed arrays containing a sub-table cannot be serialized.** `serializeValueType` throws if a value array (routed to `simpleValues`) contains a `shared_ptr<table>` element, since inline TOML cannot express it.
- **Iteration order is unspecified.** `table` iterates in `unordered_map` order, not declaration order; only the serializer imposes (lexicographic) ordering.
- **No architecture document divergences to report.** This guide documents the implementation directly; there is no separate architecture JSON whose features are unimplemented. The subset boundaries above are intentional design, not deferred work.
