# Input Parsing, Serialization & Memory Buffer Handling in `Source/JavaScriptCore`

> Analysis of external-data parsing, deserialization, and length-driven memory
> buffer handling across the JavaScriptCore tree, with emphasis on how input
> boundaries are validated and how buffer overflows / malformed-input crashes
> are prevented (or not).
>
> **Scope note:** This checkout contains `Source/JavaScriptCore` and
> `Source/WTF` (no `Source/WebCore`), plus some non-standard directories in JSC
> (`corpse/`, `lol/`, `mya/`, `testmem/`, `fuzzilli/`) that appear to be custom
> additions. WTF primitives (`LEBDecoder`, `Vector`, `Base64`, `OverflowHandler`,
> `StringImpl`) are analyzed directly from `Source/WTF/wtf` — see
> [§10](#10-wtf-primitives-actual-implementations).

---

## Table of contents

1. [Overview of the parsing surfaces](#1-overview-of-the-parsing-surfaces)
2. [Bytecode cache deserialization](#2-bytecode-cache-deserialization-runtimecachedtypescpp)
3. [WebAssembly binary parsing](#3-webassembly-binary-parsing-wasmwasmparserh)
4. [JSON parsing](#4-json-parsing-runtimejsonobjectcpp-runtimeliteralparserh)
5. [Other decoded string/binary inputs](#5-other-decoded-stringbinary-inputs)
6. [Allocations and indexing driven by incoming length fields](#6-allocations-and-indexing-driven-by-incoming-length-fields)
7. [Validation strategy in plain English](#7-validation-strategy-in-plain-english)
8. [Weaker spots and observations](#8-weaker-spots-and-observations)
9. [File index](#9-file-index)
10. [WTF primitives: actual implementations](#10-wtf-primitives-actual-implementations)

---

## 1. Overview of the parsing surfaces

| Surface | Files | Trust level of input |
|---|---|---|
| Bytecode cache (serialized `UnlinkedCodeBlock`) | `runtime/CachedTypes.cpp`, `runtime/CachedBytecode.{h,cpp}`, `runtime/CachePayload.{h,cpp}`, `runtime/BytecodeCacheError.{h,cpp}` | Mapped/embedder-supplied bytes; **semi-trusted** (version-gated, mostly unchecked structurally) |
| WebAssembly module binary | `wasm/WasmParser.h`, `wasm/WasmSectionParser.{h,cpp}`, `wasm/WasmStreamingParser.cpp`, `wasm/WasmFunctionParser.h`, `wasm/LEB128` (via WTF `LEBDecoder.h`) | Fully untrusted; **hard-fail validated** |
| JSON text | `runtime/JSONObject.cpp`, `runtime/LiteralParser.{h,cpp}`, `runtime/JSONCache.{h,cpp}` | Untrusted JS string; span-bounded |
| BigInt from strings | `runtime/JSBigInt.cpp` | Untrusted; hard length cap |
| base64 (`atob`, `Uint8Array.fromBase64`) | `jsc.cpp`, `runtime/JSGenericTypedArrayViewConstructor.cpp`, `runtime/JSGenericTypedArrayViewPrototype.cpp` | Untrusted; size estimate + clamp |
| JS source lexing | `parser/Lexer.cpp`, `parser/Parser.h` | Untrusted; pointer-cursor bounded |
| ArrayBuffer / TypedArray / DataView | `runtime/ArrayBuffer.cpp`, `runtime/ArrayBufferView.h`, `runtime/JSArrayBufferView.cpp`, `runtime/JSDataViewPrototype.cpp`, `runtime/GenericTypedArrayView*.h` | Untrusted lengths; checked arithmetic |
| Wasm/shared buffer memory | `runtime/BufferMemoryHandle.{h,cpp}`, `runtime/PageCount.h` | Bounded by address-space/3×RAM budgets |
| Mach-O corpse / exports trie (custom) | `corpse/CorpseByteParser.{h,cpp}`, `corpse/CorpseExportsTrie.cpp`, `corpse/CorpseSymbol.cpp`, `corpse/CorpseMemory.cpp` | Fully untrusted; **wrap-safe, well validated** |
| Custom additions | `lol/` (alternate JIT), `mya/` (REPL), `testmem/` (RSS tool), `fuzzilli/` (REPRL harness) | Trusted / fuzzer-fed; detail below |

---

## 2. Bytecode cache deserialization (`runtime/CachedTypes.cpp`)

This is the most security-sensitive parser in the tree: it walks serialized
bytecode (mmap'd from disk or supplied by the embedder) using **C++ structs
placed directly over the raw buffer**, with relative offsets read from the
stream itself. There is no cursor-based `Deserializer` with `readIntegral`-style
readers in this version; the design is "trusted struct layout over untrusted
bytes."

### 2.1 Entry points

**Top-level decode** — `CachedTypes.cpp:2649`:

```cpp
UnlinkedCodeBlock* decodeCodeBlockImpl(VM& vm, const SourceCodeKey& key, Ref<CachedBytecode> cachedBytecode)
{
    ...
    auto* cachedEntry = std::bit_cast<const GenericCacheEntry*>(cachedBytecode->span().data());
    Ref decoder = Decoder::create(vm, WTF::move(cachedBytecode), &key.source().provider());
    std::pair<SourceCodeKey, UnlinkedCodeBlock*> entry;
    {
        DeferGC deferGC(vm);
        if (!cachedEntry->decode(decoder.get(), entry))
            return nullptr;
    }
    if (entry.first != key)
        return nullptr;
    ...
}
```

**Validity pre-check** — `CachedTypes.cpp:2675`:

```cpp
bool isCachedBytecodeStillValid(VM& vm, Ref<CachedBytecode> cachedBytecode, const SourceCodeKey& key, SourceCodeType type)
{
    auto span = cachedBytecode->span();
    if (span.empty())
        return false;                                       // only an emptiness check, not min-size
    auto* cachedEntry = std::bit_cast<const GenericCacheEntry*>(span.data());
    Ref decoder = Decoder::create(vm, WTF::move(cachedBytecode));
    return cachedEntry->isStillValid(decoder.get(), key, tagFromSourceCodeType(type));
}
```

**Lazy function-body decode** — `CachedTypes.cpp:2685` (offsets validated once at
executable-decode time by `checkBounds`, §2.4):

```cpp
void decodeFunctionCodeBlock(Decoder& decoder, int32_t cachedFunctionCodeBlockOffset,
                             WriteBarrier<UnlinkedFunctionCodeBlock>& codeBlock, const JSCell* owner)
{
    ASSERT(decoder.vm().heap.isDeferred());
    auto* cachedCodeBlock = static_cast<const CachedWriteBarrier<CachedFunctionCodeBlock, UnlinkedFunctionCodeBlock>*>(
        decoder.ptrForOffsetFromBase(cachedFunctionCodeBlockOffset));
    cachedCodeBlock->decode(decoder, codeBlock, owner);
}
```

### 2.2 Where the external bytes come from

| Loader | File | Validation on load |
|---|---|---|
| jsc shell | `jsc.cpp:1484-1502` | **None** — mmap'd file goes straight to the decoder |
| ObjC `JSScript` | `API/JSScript.mm:167-203` | Min-size check + **trailing SHA-1 digest** + `isCachedBytecodeStillValid` |
| In-memory cache lookup | `runtime/CodeCache.h:155-179` | Whatever `SourceProvider::cachedBytecode()` returns (embedder-controlled) |

`JSScript.mm` is the gold-standard path:

```cpp
auto fileData = mappedFile->span();
// Ensure we at least have a SHA1::Digest to read.
if (fileData.size() < sizeof(SHA1::Digest)) { ... return; }
unsigned fileDataSize = fileData.size() - sizeof(SHA1::Digest);
sha1.addBytes(fileData.first(fileDataSize));
...
if (computedHash != fileHash) { FileSystem::deleteFile(cacheFilename); return; }
```

### 2.3 The buffer-walking primitives (offset-following)

**Relative offset dereference** — `CachedTypes.cpp:422` (the `m_offset` field is
read verbatim from the untrusted buffer):

```cpp
const uint8_t* LEGACY_NODELETE buffer() const
{
    ASSERT(!isEmpty());                                     // DEBUG ONLY
    return std::bit_cast<const uint8_t*>(this) + m_offset;
}
```

**Cursor helpers** — `CachedTypes.cpp:310-335` (both range checks are
**debug-only `ASSERT`**; compiled out in release, where `subspan(offset)` with an
out-of-range offset is UB):

```cpp
ptrdiff_t Decoder::offsetOf(const void* ptr)
{
    auto* addr = static_cast<const uint8_t*>(ptr);
    auto cachedBytecodeSpan = m_cachedBytecode->span();
    ASSERT(addr >= cachedBytecodeSpan.data() && addr < std::to_address(cachedBytecodeSpan.end()));
    return addr - cachedBytecodeSpan.data();
}

const void* Decoder::ptrForOffsetFromBase(ptrdiff_t offset)
{
    ASSERT(offset > 0 && static_cast<size_t>(offset) < m_cachedBytecode->size());
    return m_cachedBytecode->span().subspan(offset).data();
}
```

`CachedPtr::decode` (`:507-541`) follows `this->buffer()`, dedups decoded
pointers by buffer offset (`m_offsetToPtrMap`), and recurses. `isEmpty()` is the
sentinel `m_offset == PTRDIFF_MAX`.

### 2.4 Semantic validation (the release-mode gates)

**Version / boot-session UUID** — `CachedTypes.cpp:2519`:

```cpp
bool isUpToDate(Decoder& decoder) const
{
    if (m_cacheVersion != computeJSCBytecodeCacheVersion())   // hash of the JSC build's UUID/build-id
        return false;
    if (m_bootSessionUUID.decode(decoder) != bootSessionUUIDString())
        return false;
    return true;
}
```

`computeJSCBytecodeCacheVersion()` (`JSCBytecodeCacheVersion.cpp:53-162`) hashes
the JSC binary UUID, invalidating caches across builds. Additionally:

- `CacheEntry<...>::isStillValid` (`:2553`) decodes and compares the full
  `SourceCodeKey`; `decodeCodeBlockImpl` re-checks `entry.first != key` (`:2664`).
- Tag dispatch (`:2576-2610`) `bit_cast`s by an untrusted `m_tag` byte; unknown
  tags / eval tags hit `RELEASE_ASSERT_NOT_REACHED()` — a malformed tag is a hard
  crash, not a graceful rejection.
- **The only release-mode structural bounds check** — `checkBounds`,
  `CachedTypes.cpp:2407-2419`, in `UnlinkedFunctionExecutable`'s ctor:

```cpp
auto checkBounds = [&](int32_t& codeBlockOffset, auto& cachedPtr) {
    if (!cachedPtr.isEmpty()) {
        ptrdiff_t offset = decoder.offsetOf(&cachedPtr);
        if (static_cast<size_t>(offset) < decoder.size()) {
            codeBlockOffset = offset;
            m_isCached = true;
        }
    }
};
```

Out-of-range offsets are zeroed and the re-parse fallback is used. (Caveat: it
checks the `CachedWriteBarrier` object's own offset, not the target of its
internal `m_offset`.)

### 2.5 Stream-length-driven allocation sinks

All in `CachedTypes.cpp` unless noted. In every case the size/offset fields come
from the untrusted buffer, and payload bytes are read at `this + m_offset`
without checking `offset + count*elemSize <= bufferSize`:

| Site | Line | Behavior |
|---|---|---|
| `CachedVector::decode` | 640-649 | `vector = VectorContainer(m_size)` then indexes the mapped buffer `m_size` times, unchecked → OOB read of the mapped region |
| `CachedInstructionStream::decode` | 1526-1534 | Same, but with **`UnsafeVectorOverflow`** — deliberately skips overflow crashing for the raw bytecode stream |
| `CachedArray::decode` | 472-481 | `size` from other stream fields drives buffer indexing |
| `CachedUniquedStringImplBase` spans | 783-831 | `m_length` (×2 for 16-bit) forms a span handed to `AtomStringImpl::add`; unchecked length → OOB read |
| `CachedBitVector::decode` | 984-991 | `ensureSize(m_numBits)` + `memcpy(words, buffer, byteCount(m_numBits))` — `m_numBits` untrusted, no buffer-size check |
| `CachedBigInt::decode` | 1399-1410 | `m_length` → `tryCreateWithLength` (then **`RELEASE_ASSERT(bigInt)`** — attacker-triggerable crash) + `memcpy` of `Digit * m_length` bytes from unchecked buffer |
| `CachedScopedArgumentsTable::decode` | 1217-1223 | `m_length` drives allocation (`RELEASE_ASSERT` on failure) and copy of `m_length` `ScopeOffset`s |
| `CachedImmutableButterfly::decode` | 1322-1334 | Attacker-controlled `m_indexingType` + `m_length` drive butterfly allocation *and* which decode path runs |
| `CachedExpressionInfo::decode` | 1073-1083 | Three untrusted counts → `FastMalloc` in `bytecode/ExpressionInfo.cpp:818-823` (no null-check) |
| `CachedMetadataTable::decode` / `UnlinkedCodeBlock` ctor | 1556-1574, 2253-2290 | `m_numValueProfiles`, `numVars`, `numCalleeLocals`, etc. size metadata Vectors during cell construction |
| `CachedJSValue::decode` | 1472-1516 | Untrusted enum byte selects struct interpretation; out-of-range → `RELEASE_ASSERT_NOT_REACHED()` |

Writer-side contrast: `Encoder::malloc` (`:111-119`) and `Page::malloc`
(`:215-226`) have real capacity checks (`RELEASE_ASSERT`, `offset + size >
capacity()`) — the reader side has no counterpart.

---

## 3. WebAssembly binary parsing (`wasm/WasmParser.h`)

The wasm parser is the disciplined counterpart to the bytecode cache: every
read is bounds-checked against a `std::span<const uint8_t>` and returns `false`
on failure. All logic is header-inline in `ParserBase`; LEB128 lives in WTF's
`<wtf/LEBDecoder.h>` (`Source/WTF/wtf/LEBDecoder.h` — full analysis with the
actual implementation in [§10.1](#101-leb128-decoding-wtflebdecoderh)).

### 3.1 Cursor state and failure plumbing

```cpp
size_t m_offset = 0;                       // cursor into the source (WasmParser.h:97)
std::span<const uint8_t> m_source;         // the slice this parser may read (h:122)

#define WASM_PARSER_FAIL_IF(condition, ...) do {        // h:105
    if (condition) [[unlikely]]
        return fail(__VA_ARGS__);
} while (0)
#define WASM_ALLOCATOR_FAIL_IF(condition, ...) do { ... }  // h:110 — alloc failure == parse failure
```

### 3.2 Checked readers (all `[[nodiscard]] bool`)

**UTF-8 strings with overflow-safe length check and fallible allocation** —
`WasmParser.h:170-187`:

```cpp
ALWAYS_INLINE bool ParserBase::consumeUTF8String(Name& result, size_t stringLength)
{
    if (!stringLength)
        return true;
    if (m_source.size() < stringLength || m_offset > m_source.size() - stringLength)  // subtraction form: no wrap
        return false;
    if (!result.tryReserveCapacity(stringLength))    // OOM -> parse failure, not crash
        return false;

    auto string = byteCast<char8_t>(m_source.subspan(m_offset, stringLength));
    if (auto checkResult = WTF::Unicode::checkUTF8WithoutUTF16Length(string); checkResult.size() != string.size())
        return false;                                // real UTF-8 validation before copy

    result.grow(string.size());
    memcpySpan(result.mutableSpan().last(string.size()), string);
    m_offset += string.size();
    return true;
}
```

**LEB128 delegation** — `WasmParser.h:189-213`:

```cpp
ALWAYS_INLINE bool ParserBase::parseVarUInt32(uint32_t& result)
{
    return WTF::LEBDecoder::decodeUInt32(m_source, m_offset, result);
}
ALWAYS_INLINE bool ParserBase::peekVarUInt32(uint32_t& result)
{
    SetForScope savedOffset(m_offset, m_offset);   // restores offset on failure
    return parseVarUInt32(result);
}
// parseVarUInt64 / parseVarInt32 / parseVarInt64 identical pattern
```

The actual `wtf/LEBDecoder.h` implementation (audited in
[§10.1](#101-leb128-decoding-wtflebdecoderh)) caps u32 at 5 bytes / u64 at 10
bytes (`maxByteLength<T>() = (numBits - 1) / 7 + 1`), rejects overlong encodings
(`if (i == last) return false`), rejects final-byte overflow bits
(`byte & lastByteMask<T>()`), and for signed LEBs rejects non-canonical sign
extension before sign-extending. On failure the offset has advanced, but every
caller treats `false` as a hard parse failure and never uses `result`.

**Fixed-width reads** — `WasmParser.h:215-240`:

```cpp
ALWAYS_INLINE bool ParserBase::parseUInt32(uint32_t& result)
{
    if (m_source.size() < m_offset + 4)          // safe: m_offset <= size() invariant
        return false;
    memcpy(&result, m_source.data() + m_offset, sizeof(uint32_t));  // src can be unaligned
    m_offset += 4;
    ...
}
```

**Single-byte readers** — `WasmParser.h:250-293`: `parseUInt8` / `parseInt7`
(check `m_offset >= m_source.size()`; `parseInt7` also rejects >7-bit encodings
via `!(v & 0x80)`), `peekUInt8`, `parseUInt7` (`result < 0x80`),
`parseVarUInt1` (decodes u32 then range-checks `temp > 1`).

**Heap-type indices** — `parseHeapType` (`:295-314`) checks the decoded index
against `info.typeCount()` — no unchecked type-index use.

### 3.3 Streaming parser: section lengths gate everything

**Module size cap (Checked arithmetic)** — `WasmStreamingParser.cpp:308-312`:

```cpp
m_totalSize += bytes.size();
if (m_totalSize.hasOverflowed() || m_totalSize > maxModuleSize) [[unlikely]] {   // maxModuleSize = 1 GiB
    m_state = fail("module size is too large, maximum "_s, maxModuleSize);
```

Section payloads are staged byte-by-byte into `Vector<uint8_t> m_remaining`
(`consume`, `:231-261`, bounded by the 1 GiB cap), then handed to `SectionParser`
as an **exact-size span** (`:201-224`), with mandatory full consumption:

```cpp
WASM_STREAMING_PARSER_FAIL_IF(parser.source().size() != parser.offset(),
    "parsing ended before the end of "_s, m_section, " section"_s);
```

**Code section** — `:151-177`: function count is pinned to the already-capped
Function-section count (`functionCount != m_info->functions.size()` → fail), and
each body is capped at `maxFunctionSize = 7654321` bytes. `finalize()`
(`:425-468`) cross-checks parsed-vs-declared function counts, Data Count vs. Data
section, and requires full consumption.

### 3.4 Section parser: counts capped, then fallible reserve

`WasmSectionParser.cpp` — every count-driven allocation follows
**decode → cap against `WasmLimits.h` → `tryReserve…`**:

| Section | Line | Cap |
|---|---|---|
| Type | 53-56 | `maxTypes` = 1e6 |
| Import | 146-155 | `maxImports` = 1e6 |
| Function | 238-248 | `maxFunctions` = 1e6; type index bounds-checked |
| Table | 318, 379 | `maxTables` = 1e5 (per-table size deferred, see §8) |
| Memory | 398, 433-439 | `maxMemories` = 100 |
| Global | 454-458 | `maxGlobals` = 1e6 |
| Export | 500-543 | `maxExports` = 1e6; index-space bounds per kind |
| Element | 571-574, 1268-1278 | `maxTableEntries` = 1e7; `static_assert(maxTableEntries < UINT32_MAX)` |
| Data | 1350-1381 | `maxDataSegments` = 1e5; `dataByteLength > maxModuleSize` rejected |
| DataCount | 1439-1440 | `maxDataSegments`; cross-checked vs. Data section |
| Exception | 1449-1452 | `maxExceptions` = 1e6 |

Representative data-section snippet (`:1372-1381`) — underflow-safe copy bounds:

```cpp
WASM_PARSER_FAIL_IF(!parseVarUInt32(dataByteLength), ...);
WASM_PARSER_FAIL_IF(dataByteLength > maxModuleSize, ...);
auto segment = Segment::tryCreate(*initExpr, dataByteLength, Segment::Kind::Active);
WASM_PARSER_FAIL_IF(!segment, "can't allocate enough memory ...");
WASM_PARSER_FAIL_IF(source().size() < dataByteLength || (source().size() - dataByteLength) < m_offset, ...);
memcpySpan(segment->span(), source().subspan(m_offset, dataByteLength));
m_offset += dataByteLength;
```

`Segment::tryCreate` (`wasm/WasmFormat.cpp:49-58`) uses
`tryFastZeroedMalloc` and returns `nullptr` on OOM — no crash path. Resizable
limits (`:270-314`) validate flag bits (`~0x07` mask), reject shared/64-bit
without options, enforce `initial <= maximum`, and require shared-to-have-max.
GC/type-section paths add `maxRecursionGroupCount`, `maxSubtypeDepth = 63`,
`maxFunctionParams/Returns = 1000`, and `Checked<unsigned, RecordOverflow>` for
struct payload sizes (`:984-995`).

**Custom sections** (`:1471-1505`): payload = entire remaining section bytes,
copied with `tryReserveInitialCapacity` + `memcpySpan` — bounded by the 1 GiB
module cap but the largest single allocation the parser accepts.

### 3.5 Custom-section sub-parsers

- **Name section** (`wasm/WasmNameSectionParser.cpp:46-47, 73, 101`):
  `payloadLength > source().size() - m_offset` (underflow-safe) → fail;
  function indices bounds-checked before store; exact-size required. Failures
  are **non-fatal by design** (`WasmSectionParser.cpp:1493` — warning logged).
- **Branch hints** (`wasm/WasmBranchHintsSectionParser.cpp:40-70`): counts
  self-limit (each iteration consumes ≥3 bytes); monotonicity of function
  indices and branch offsets enforced; result discarded at the call site
  (`WasmSectionParser.cpp:1496: std::ignore = ...parse();`) — non-fatal.
- **Source mapping URL** (`wasm/WasmSourceMappingURLSectionParser.cpp:38-42`):
  length-prefixed string via the safe `consumeUTF8String`.

### 3.6 Function bodies (`wasm/WasmFunctionParser.h:497-513, 592-593`)

```cpp
uint64_t totalNumberOfLocals = signature.argumentCount();    // 64-bit accumulator: no 32-bit wrap
for (uint32_t i = 0; i < localGroupsCount; ++i) {
    ...
    WASM_PARSER_FAIL_IF(!parseVarUInt32(numberOfLocals), ...);
    totalNumberOfLocals += numberOfLocals;
    WASM_PARSER_FAIL_IF(totalNumberOfLocals > maxFunctionLocals, ...);   // 50,000, checked BEFORE reserve
    ...
}
WASM_ALLOCATOR_FAIL_IF(!m_locals.tryReserveCapacity(totalNumberOfLocals), ...);
...
if (Context::validateFunctionBodySize)
    WASM_PARSER_FAIL_IF(m_offset != source().size(), "function body size doesn't match the expected size");
```

### 3.7 Memory/table instantiation guards

- `wasm/WasmLimits.h:47-97` holds all constants: `maxModuleSize = 1 GiB`,
  `maxFunctionSize = 7654321`, `maxFunctionLocals = 50000`, `maxArraySizeInBytes = 1<<30`, etc.
- `runtime/PageCount.h:61-66`: `bytes()` **saturates** at `UINT64_MAX` instead of
  wrapping; `fromBytes()` `RELEASE_ASSERT`s validity.
- `wasm/WasmMemory.cpp:159-182`: `Memory::tryCreate` checks
  `initialBytes > allocatableBytes` and routes through
  `BufferMemoryManager::tryAllocatePhysicalBytes` (fallible).
- `wasm/WasmTable.h:84` / `WasmTable.cpp:98-151`: `isValidLength` caps at
  `maxTableEntries`; `tryCreate` returns `nullptr` if invalid; `grow` uses
  `CheckedUint64`/`CheckedUint32` for `length + delta` and
  `reallocSize * sizeof(element)` overflow detection.

---

## 4. JSON parsing (`runtime/JSONObject.cpp`, `runtime/LiteralParser.{h,cpp}`)

Entry point — `JSONObject.cpp:2242-2279`:

```cpp
JSValue JSONParse(JSGlobalObject* globalObject, StringView json)
{
    if (json.isNull())
        return JSValue();
    if (json.is8Bit()) {
        LiteralParser<Latin1Character, JSONReviverMode::Disabled> jsonParser(globalObject, json.span8(), StrictJSON);
        return jsonParser.tryLiteralParse();
    }
    LiteralParser<char16_t, JSONReviverMode::Disabled> jsonParser(globalObject, json.span16(), StrictJSON);
    return jsonParser.tryLiteralParse();
}
```

`jsonProtoFuncParse` (`:2198`) feeds `JSON.parse`; the actual parsing lives in
`runtime/LiteralParser.{h,cpp}` in this checkout (not WTF `JSONImpl`).
`runtime/JSONCache.{h,cpp}` is an in-memory atom/transition micro-cache for
`JSON.parse`/`stringify` — it reads **no serialized bytes**.

Validation in `LiteralParser`:

- **Span-bounded lexer** — `LiteralParser.h:209-231`: `m_ptr`/`m_end` from
  `std::span<const CharType>`; `peek()` past end returns `CharType{}`;
  `advance(length)` asserts `length <= m_end - m_ptr`.
- **Stack-limited recursion** — `LiteralParser.cpp:1572-1576`: falls back to a
  non-recursive/slow path when `currentStackPointer() < vm.softStackLimit()`
  (limits at `:1472, 1490, 1508`).
- **Overflow-checked accumulation** — `:1602-1607`:
  `m_elementStack.append(value); if (m_elementStack.hasOverflowed()) { ... throwOutOfMemoryError ... }`.
- `materializeArray` (`:1513-1567`) allocates one JSArray at the collected
  length and reports OOM rather than crashing.

Stringify side: `FastStringifier` (`JSONObject.cpp:834-991`) bounds its buffer
by remaining stack capacity (`usableBufferSize`, `:834-899`) and, for the
dynamic buffer, checks `StringImpl::isValidLength<CharType>(newSize)` and uses
`tryGrow` (`:980-985`) — no unchecked growth.

---

## 5. Other decoded string/binary inputs

### 5.1 BigInt from strings (`runtime/JSBigInt.cpp`)

Hard size cap — `JSBigInt.h:516-522`:

```cpp
static constexpr unsigned maxLengthBits = 1024 * 1024;   // 1 Mbit
static constexpr unsigned maxLength = maxLengthBits / digitBits;
```

`createWithLength` rejects `length > maxLength` before allocation
(`JSBigInt.cpp:98-121`). The string parse (`:5694-5880`, dispatched from
`parseInt`/`stringToBigInt` at `:377-394`) computes a digit-count estimate from
the input length with a triple guard (`:5800-5871`):

```cpp
auto computeLength = [](size_t bitsPerChar, unsigned charcount) -> std::optional<unsigned> {
    size_t chars = charcount;
    const unsigned roundup = bitsPerCharTableMultiplier - 1;
    if (chars <= (std::numeric_limits<size_t>::max() - roundup) / bitsPerChar) {  // pre-divide overflow guard
        size_t bitsMin = bitsPerChar * chars;
        bitsMin = (bitsMin + roundup) >> bitsPerCharTableShift;
        if (bitsMin <= static_cast<size_t>(maxInt)) {
            unsigned length = (bitsMin + digitBits - 1) / digitBits;
            if (length <= maxLength)     // <-- 1 Mbit cap
                return length;
        }
    }
    return std::nullopt;
};
```

Trailing whitespace is removed by shrinking the span (`data = data.first(data.size() - 1)`,
`:5701-5703`) so every read stays provably in-bounds; per-character accumulation
uses `Checked<uint64_t, CrashOnOverflow>` (`:5805-5806`). Other
length-driven vectors (e.g. `multiplyImpl`, `:2519-2560`) re-check
`result.size() > maxLength`.

### 5.2 base64 / atob

- **`atob` shim** — `jsc.cpp:1742-1765`: converts to a WTF string, calls
  `base64DecodeToString(encodedString, { ValidatePadding, IgnoreWhitespace })`,
  and treats a null result as a syntax error. The actual decoder is
  `base64DecodeInternal` in `Source/WTF/wtf/text/Base64.cpp:208-287` (audited in
  [§10.3](#103-base64-wtfwtf-textbase64cpp)): it allocates the output Vector at
  the *input* length (a safe upper bound — 4 base64 chars shrink to 3 bytes),
  decodes in place with padding/whitespace/alphabet validation, and shrinks to
  the actual decoded length before returning; all failure paths return
  `std::nullopt`.
- **`Uint8Array.fromBase64`** — `JSGenericTypedArrayViewConstructor.cpp:89-104`:

```cpp
Vector<uint8_t, 128> output;
output.grow(maxLengthFromBase64(view));     // simdutf-computed exact upper bound from input length (§10.3)
auto [shouldThrowError, readLength, writeLength] =
    fromBase64(view, output.mutableSpan(), alphabet, lastChunkHandling, WTF::OutputSizeIsMaxLength::No);
...
JSUint8Array* uint8Array = JSUint8Array::createUninitialized(..., writeLength);
memcpySpan(uint8Array->typedSpan(), output.span().first(writeLength));
```

The typed array is allocated at the *actual* `writeLength`, so an over-estimated
upper bound cannot inflate the JS-visible length.

- **`setFromBase64`** — `JSGenericTypedArrayViewPrototype.cpp:95-106`: writes
  directly into `std::span { typedVector(), length() }` with
  `OutputSizeIsMaxLength::Yes` after a detached/OOB check via
  `isIntegerIndexedObjectOutOfBounds`. Hex variants bound with
  `std::min(view.length() / 2, uint8Array->length())` (`:139-140`).
  `toBase64` (`:196-208`) uses `base64EncodeToStringReturnNullIfOverflow`.

### 5.3 Lexer (`parser/Lexer.cpp`)

`setCode` (`:548-580`) sets pointer bounds from the source `StringView`:
`m_code = m_codeStartPlusOffset`, `m_codeEnd = m_codeStart + source.endOffset()`.
`shift()` (`:589-597`), `atEnd()` (`:599-608`), and `peek(offset)`
(`:610-616`, asserted `offset < 5`) all clamp to `m_codeEnd` and substitute
`T{}` past the end, so an external string cannot be read past its length.
Token/lex buffers (`m_buffer8/m_buffer16`) are WTF `Vector`s (CrashOnOverflow).
Number lexing accumulates digits one char at a time via `record8`, with
`numberOfDigitsForSafeInt52 = 15` (`Lexer.h:195`) capping the double fast path
before falling back to BigInt string tokens re-parsed by the guarded
`JSBigInt::parseInt` (§5.1). Nit: token offsets are 32-bit `int`
(`Lexer.h:141`) — consistent with the String length cap, but would truncate for
hypothetical >2 GB sources.

### 5.4 Mach-O corpse / exports trie (custom `corpse/` code)

**`ByteParser`** — `corpse/CorpseByteParser.cpp:37-66` — a non-allocating,
bounds-checked cursor over an untrusted `std::span<const uint8_t>`. Failed
reads consume nothing (position rolled back):

```cpp
std::optional<uint8_t> ByteParser::consumeByte()
{
    if (m_position >= m_data.size())
        return std::nullopt;
    return m_data[m_position++];
}

std::optional<uint64_t> ByteParser::consumeULEB128()
{
    size_t start = m_position;
    uint64_t result = 0;
    if (WTF::LEBDecoder::decodeUInt64(m_data, m_position, result))
        return result;
    m_position = start;
    return std::nullopt;
}

std::optional<std::string_view> ByteParser::consumeCString()
{
    size_t start = m_position;
    while (m_position < m_data.size() && m_data[m_position])
        ++m_position;
    if (m_position >= m_data.size()) {
        m_position = start;
        return std::nullopt;
    }
    std::string_view result(spanReinterpretCast<const char>(m_data.subspan(start, m_position - start)));
    ++m_position; // Consume the null terminator.
    return result;
}
```

Header comments (`CorpseByteParser.h:52-60`) explicitly state why truncation must
be *rejected* rather than silently truncated: "Untrusted data can hold either,
and silently truncating one would yield a plausible wrong value instead of a
detected failure." Returned `string_view`s alias the input span — no copy, no
allocation. Adversarial unit tests in
`corpse/tests/CorpseByteParserTest.cpp:48-179`.

**`ExportsTrie::lookUp`** — `corpse/CorpseExportsTrie.cpp:43-138` — the dyld
exports-trie walk. Wrap-safe terminal-length check (`:58-68`):

```cpp
auto terminalLength = node.consumeULEB128();
if (!terminalLength)
    return makeUnexpected(Failure::Malformed);
// terminalLength is a full 64-bit value out of the trie, so it is compared
// against what is left of the trie rather than by forming position + terminalLength,
// which could wrap and pass a direct comparison.
if (*terminalLength > trie.size() - node.position())
    return makeUnexpected(Failure::Malformed);
size_t childrenPosition = node.position() + *terminalLength;
```

The terminal payload is parsed through a **sub-bounded parser**
(`trie.subspan(node.position(), *terminalLength)`), flags are masked against
known Mach-O bits (`*flags & ~knownExportFlagBits` → Malformed), and the child
walk (`:106-134`) bounds-checks the child count byte, every edge C-string
(**empty edges rejected** — they would match anything and consume nothing,
yielding a non-terminating walk), and every child ULEB offset. The loop is
provably bounded because every iteration must consume ≥1 character of the search
name. Adversarial tests in `corpse/tests/CorpseExportsTrieTest.cpp:488-625`
cover: a never-ending ULEB terminal length (`Vector<uint8_t> trie { 0x80 }`),
terminal longer than trie, lengths that would *wrap* `position`, truncated
flags, ULEBs running past the terminal, empty edges, never-ending child offsets,
and edges outside the trie.

**`CorpseSymbol.cpp`** — Mach-O load-command walking: `readCommand<T>`
(`:89-102`) bounds-checks with subtraction form before `memcpySpan` into a local
struct; sanity caps at `:79-87` (`maxLoadCommandsSize = 128 KB`,
`maxExportsTrieSize = 16 MB`, `maxImageCount = 16K`) plus a per-lookup
`maxTotalBytesRead = 256 MB` budget (`:114-122`) so a hostile corpse cannot force
unbounded mapping; the trie is verified to sit inside `__LINKEDIT` (`:226-234`,
wrap-safe).

**`CorpseMemory.cpp`** — `Memory::map` (`:136-181`) checks zero size,
`objBase + objSizeInBytes` overflow, and end-of-address-space overflow before
`mach_vm_remap_new`; reads go through checked `Ptr`/`Span` views. Errors are
typed enums (`Memory::Error`, `ExportsTrie::Failure`) — all "report and bail,"
never "guess."

---

## 6. Allocations and indexing driven by incoming length fields

### 6.1 ArrayBuffer / TypedArray / DataView (`runtime/`)

**The canonical overflow guard** — `ArrayBuffer.cpp:199-228`
(`ArrayBufferContents::tryAllocate`):

```cpp
CheckedSize sizeInBytes = numElements;
sizeInBytes *= elementByteSize;
if (sizeInBytes.hasOverflowed() || sizeInBytes.value() > MAX_ARRAY_BUFFER_SIZE) {
    reset();
    return;
}
size_t allocationSize = sizeInBytes.value();
if (!allocationSize)
    allocationSize = 1;   // null means detached
...
RELEASE_ASSERT(m_sizeInBytes <= MAX_ARRAY_BUFFER_SIZE);   // line 224
```

`MAX_ARRAY_BUFFER_SIZE` (`PageCount.h:37-45`) is `1ull << 34` (16 GiB) with
`USE(LARGE_TYPED_ARRAYS)`, else `0x7fffffff` (2 GB on 32-bit). The resizable
path (`ArrayBuffer.cpp:376-401`) adds
`sizeInBytes.value() > maxByteLength.value() || maxByteLength.value() > MAX_ARRAY_BUFFER_SIZE`
→ nullptr; the shared path `tryCreateShared` (`:644-657`) has the same triple
check. `ArrayBuffer::create` (`:272-278, 358-364`) is `tryCreate` + `CRASH()` on
failure. Resizable reservation is bounded by `maxGrowableBufferReservationBytes`
(`:108-121`). `resize` (`:556-642`) and `SharedArrayBufferContents::tryGrow`
(`:692-764`) re-check `newByteLength <= m_maxByteLength`,
`<= mappedCapacity()`, and `newPageCount.bytes() <= MAX_ARRAY_BUFFER_SIZE`.

**Overflow-free sub-range verification** — `ArrayBufferView.h:143-157`
(subtract-then-divide; **never multiplies**):

```cpp
static bool verifySubRangeLength(size_t byteLength, size_t byteOffset, size_t numElements, unsigned elementSize)
{
    if (byteOffset > byteLength)
        return false;
    size_t remainingElements = (byteLength - byteOffset) / static_cast<size_t>(elementSize);
    if (numElements > remainingElements)
        return false;
    return true;
}
```

Used by `DataView::wrappedAs` (`DataView.cpp:57-65`, incl. growable-shared
hardening against `maxByteLength`), `GenericTypedArrayView::wrappedAs`
(`GenericTypedArrayViewInlines.h:88-108`), `JSDataView::create`
(`JSDataView.cpp:59-67`), and `JSGenericTypedArrayView::create`
(`JSGenericTypedArrayViewInlines.h:120-128`, plus `verifyByteOffsetAlignment`).

`clampOffsetAndNumElements` (`ArrayBufferView.h:175-198`) uses
`maxOffset = (SIZE_MAX - arrayByteOffset) / sizeof(T)` and a `CheckedSize` for
`offset * sizeof(T) + arrayByteOffset`, clamping to OOB instead of wrapping. The
`ArrayBufferView` ctor (`ArrayBufferView.cpp:45-57`) release-asserts
`byteOffset + byteLength <= buffer->byteLength()` via
`Checked<size_t, CrashOnOverflow>` (`RELEASE_ASSERT_WITH_SECURITY_IMPLICATION`).
`setImpl/setRangeImpl/getRangeImpl/zeroRangeImpl` (`ArrayBufferView.h:226-267`)
gate every `memmove/memset` with
`isSumSmallerThanOrEqual(byteOffset, dataByteLength, byteLength())`.

**JSArrayBufferView storage** (`JSArrayBufferView.cpp:60-107`):

```cpp
CheckedSize size = length;
size *= elementSize;
if (size.hasOverflowed() || size > MAX_ARRAY_BUFFER_SIZE)
    return;    // leaves m_structure null -> caller throws OOM
```

Fast path (`length <= 1000`) `RELEASE_ASSERT`s the limit; the backing pointer is
a `CagedBarrierPtr<Gigacage::Primitive, void>` (`JSArrayBufferView.h:192`) so
even a wrong offset is Gigacage-confined.

**DataView per-access bounds** (`JSDataViewPrototype.cpp:156-163 getData,
204-211 setData`):

```cpp
IdempotentArrayBufferByteLengthGetter<std::memory_order_relaxed> getter;
auto byteLengthValue = dataView->viewByteLength(getter);
if (byteLengthValue) [[unlikely]]
    return throwVMTypeError(..., typedArrayBufferHasBeenDetachedErrorMessage);
size_t byteLength = byteLengthValue.value();
if (elementSize > byteLength || byteOffset > byteLength - elementSize)   // subtraction form: no overflow
    return throwVMRangeError(globalObject, scope, "Out of bounds access"_s);
```

The length is **re-read per access** (`viewByteLength`, `JSDataView.h:58-81`,
returns `nullopt` when detached or when `byteLengthRaw() + byteOffset >
bufferByteLength`), so a concurrently resized buffer is re-validated every call.
Typed-array range copies (`JSGenericTypedArrayViewInlines.h:184-283`) clamp
`length = std::min(length, other->length())`, then
`RELEASE_ASSERT(other->canAccessRangeQuickly(...))` + `validateRange` before
copying, with `Checked<size_t> sizeToAllocate = length; sizeToAllocate *= sizeof(Type)`.

### 6.2 Wasm/shared buffer memory (`runtime/BufferMemoryHandle.{h,cpp}`)

Three independent bounds, none derived directly from untrusted input except
through the already-capped ArrayBuffer layer:

- `maxGrowableBufferReservationBytes = Gigacage::primitiveAddressSpaceBudget / 4`
  (`BufferMemoryHandle.h:63-69`), with a `static_assert` tying it to
  `PageCount::maxMemory32Bytes`.
- `memoryLimit()` (`h:113-118`) = `ramSize() * 3`, guarded by
  `productOverflows<size_t>(ramSize(), 3)`; physical-bytes accounting
  (`BufferMemoryHandle.cpp:198-216`) holds `m_physicalBytes + bytes >
  memoryLimit()` → `SyncTryToReclaimMemory` under `m_lock` (GC retry, not a raw
  allocation).
- Fixed fast-memory count (`m_maxFastMemoryCount`, `:82-108`) and fixed
  `fastMappedBytes()` (`:59-75`).

`isInGrowableOrFastMemory` (`:174-194`) does binary-search range checks for the
wasm bounds-check fault handler.

### 6.3 Summary table: untrusted length → allocation

| Component | Length source | Guard before allocation | Failure mode |
|---|---|---|---|
| ArrayBuffer `numElements * elemSize` | JS arg / C API | `CheckedSize` overflow flag + `MAX_ARRAY_BUFFER_SIZE` | nullptr / OOM exception |
| Typed array views | offset/length args | `verifySubRangeLength` (subtract-then-divide), alignment checks | RangeError |
| DataView get/set | offset arg | `byteOffset > byteLength - elementSize` per access, resize-aware | RangeError |
| BigInt strings | input string length | size_t overflow guard + `maxInt` + 1 Mbit `maxLength` | OOM exception |
| base64 decode | input string length | output buffer sized at input length (4→3 never grows) or `simdutf`-computed bound; copy clamped to `writeLength` (§10.3) | null / exception |
| JSON element stack | token count | `hasOverflowed()` + soft stack limit | OOM exception / RangeError |
| Wasm sections | LEB counts | `WasmLimits.h` constants + `tryReserve…` + `WASM_ALLOCATOR_FAIL_IF` | parse error / JS exception |
| Wasm memory/tables | page counts | `maxDeclarablePageCount`, `CheckedUint64`, `isValidLength` | nullptr → instantiation error |
| Bytecode cache vectors | stream `m_size`/`m_length` | Vector CrashOnOverflow only (release); **no buffer-size check** | OOB read / `RELEASE_ASSERT` (see §8) |
| Corpse trie/symbols | ULEB values | subtraction-form checks + 128 KB/16 MB/16 K/256 MB caps | `Failure::Malformed` |

---

## 7. Validation strategy in plain English

The codebase uses **five consistent defense patterns**, applied unevenly by
subsystem:

1. **Span-bounded cursors with checked reads.** The wasm parser and the corpse
   `ByteParser` never hold a raw pointer plus a separate size; they hold one
   `std::span`, and *every* read first asks "is there a byte left?" and returns
   a failure value if not. Failed reads roll the cursor back, so a rejected read
   consumes nothing and can't half-advance the parser into an inconsistent state.

2. **Overflow-safe arithmetic.** Bounds checks are written in **subtraction
   form** — `if (length > total || offset > total - length)` instead of
   `offset + length > total` — because `offset + length` can wrap around a
   64-bit integer and pass the check for a hostile value. Length-driven
   multiplications (like `numElements * elementByteSize`) use
   `Checked`/`CheckedSize` arithmetic that sets an overflow flag instead of
   silently wrapping; anything that overflows is rejected *before* allocation.
   64-bit accumulators (e.g. wasm local counts) prevent 32-bit wrap on the way
   up.

3. **Caps before allocation, and fallible allocation.** Counts read from a
   stream are always checked against a hard constant *before* memory is
   reserved: `MAX_ARRAY_BUFFER_SIZE` for JS buffers; `maxModuleSize = 1 GiB`,
   `maxFunctions = 1e6`, `maxTableEntries = 1e7`, etc. for wasm; the 1-Mbit
   `maxLength` for BigInt; 128 KB / 16 MB / 16 K / 256 MB sanity caps in the
   corpse Mach-O reader. Reservations use `tryReserve…`/`tryCreate`/
   `tryFastZeroedMalloc`, so running out of memory produces a JS exception or a
   parse error — never a null-deref crash.

4. **Semantic validation at the boundary.** Bytecode caches are rejected
   outright if the build-UUID hash (`computeJSCBytecodeCacheVersion`) or
   boot-session UUID doesn't match, and the decoded `SourceCodeKey` must equal
   the requested key — a stale or forged cache falls back to re-parsing source.
   The `JSScript.mm` loader adds a SHA-1 integrity check. JSON rejects
   malformed tokens lexically. Wasm sections must be *fully* consumed
   (`source().size() != offset()` is fatal), so trailing garbage or truncated
   payloads are detected; wasm cross-checks declared counts between sections
   (Function vs. Code, DataCount vs. Data). UTF-8 strings are validated, not
   just length-checked.

5. **Fail-closed, never "best effort."** Malformed input yields
   `false`/`nullptr`/a typed error enum (`Failure::Malformed`,
   `BytecodeCacheError`), not a truncated or coerced value. The corpse code's
   header comments state this explicitly: silently truncating an over-long
   ULEB128 "would yield a plausible wrong value instead of a detected failure."
   Auxiliary wasm sections (names, branch hints, sourceMappingURL) are
   deliberately **non-fatal** — a bad name section degrades gracefully rather
   than killing the module.

---

## 8. Weaker spots and observations

1. **The bytecode cache decoder (`CachedTypes.cpp`) is the outlier.** It treats
   the mmap'd cache file as essentially trusted:
   - The offset-following primitive `this + m_offset` (`:422-433`) and the
     `Decoder::offsetOf` / `ptrForOffsetFromBase` range checks (`:310-335`) are
     **debug `ASSERT`-only** — compiled out in release.
   - Untrusted `m_size`/`m_length` fields drive both heap allocations *and*
     indexing into the mapped buffer with no release-mode check that the buffer
     actually holds that many elements (`CachedVector::decode` `:640-649`,
     `CachedBitVector` memcpy `:988-990`, `CachedBigInt` `:1404-1408`, string
     spans `:821-822`). Release-mode safety rests on the version/UUID/key gate
     plus the OS's page-granular mmap, not on per-field bounds checks.
   - `CachedInstructionStream` deliberately opts out of overflow crashing via
     `UnsafeVectorOverflow` (`:1528-1534`).
   - Malformed tags/types and allocation failures are `RELEASE_ASSERT` /
     `RELEASE_ASSERT_NOT_REACHED()` — **crash-on-malformed, not reject** — and
     can be triggered by any input that passes the version gate.
   - The jsc-shell loader (`jsc.cpp:1484-1502`) performs no content validation
     on load at all; only `JSScript.mm` adds SHA-1 + min-size validation first.
   - The offset-keyed dedup map (`m_offsetToPtrMap`) has no type tagging — a
     forged offset colliding with a previously decoded one can resolve to a
     wrong-type object.
   - `BytecodeCacheError` (`:32-73`, `.cpp:33-87`) models only writer-side
     errors; there is no "malformed cache data" error variant.

2. **Wasm per-table size cap is deferred.** A table's individual `initial` size
   is not capped in `parseTableHelper`; the cap is enforced at instantiation in
   `WasmTable::tryCreate`. Spec-legal, but a module can validate with a
   near-`maxTableEntries` table and only then fail allocation (relevant for
   resource-exhaustion analysis, not memory safety).

3. **Wasm custom sections can copy up to ~1 GiB** into
   `ModuleInformation::customSections` (payload = whole remaining section) —
   bounded by `maxModuleSize`, but the largest single allocation the parser
   accepts.

4. **`testmem/readScript`** (`testmem/testmem.cpp:68-84`) uses unchecked
   `ftell`/`fread` into `std::vector<char>(length + 1)` — no check for negative
   length or short reads. Input here is a trusted local test file, not
   adversarial, but it's the one unchecked read-f-file in the custom code.

5. **`fuzzilli/Fuzzilli.cpp`** (REPRL harness) reads fuzzer commands from fixed
   fds 100-103 into a 16 MB `REPRL_MAX_DATA_SIZE` buffer with
   `RELEASE_ASSERT`ed full-length reads — assumes a faithful fuzzer controller
   by design.

6. **`lol/`** (`LOLJIT`, `LOLJITOperations`, `LOLRegisterAllocator.h`) is an
   experimental alternate baseline JIT (subclasses `JSC::JIT`, small op set via
   `FOR_EACH_IMPLEMENTED_OP`). It compiles bytecode, not external bytes — no
   untrusted buffer handling. **`mya/mya.cpp`** is an interactive CLI over the
   Corpse library with a hand-rolled text lexer; `consumeUint32` validates via
   `strtol` with `errno` checks and `INT_MAX` caps.

7. **`GenericTypedArrayViewInlines.h:82`** does an unchecked
   `length * sizeof(Type)` multiply in a `memcpy` — safe only because
   `tryCreate(length)` already succeeded for exactly that product (invariant,
   not a local guard).

8. **WTF `UnsafeVectorOverflow` is debug-only.** The `CachedInstructionStream`
   vector (`CachedTypes.cpp:1528-1534`) is typed
   `Vector<uint8_t, 0, UnsafeVectorOverflow, ...>`; per
   [§10.2](#102-vector-internals-wtfwtfvectorh), that handler's `overflowed()`
   is an `ASSERT_NOT_REACHED_WITH_SECURITY_IMPLICATION()` — compiled out in
   release. Combined with the debug-only offset checks in the cache decoder, a
   corrupt stream-size field there is unchecked in release builds. (The
   allocation itself still goes through `allocateBuffer`, which hard-caps
   capacity via `isValidCapacityForVector`, so this is an OOB *read* of the
   mapped cache region, not a wrapping allocation.)

---

## 9. File index

**Bytecode cache**
- `runtime/CachedTypes.cpp` / `.h` — decode entry points, `Decoder`, `Cached*` mirror structs
- `runtime/CachedBytecode.cpp` / `.h` — buffer wrapper
- `runtime/CachePayload.cpp` / `.h` — `MallocSpan` / `MappedFileData` variant
- `runtime/BytecodeCacheError.cpp` / `.h` — writer-side error model
- `runtime/JSCBytecodeCacheVersion.cpp` / `.h` — build-UUID hash
- `runtime/CodeCache.h` — in-memory lookup path
- `bytecode/UnlinkedFunctionExecutable.cpp` — `decodeCachedCodeBlocks` / `checkBounds` consumer
- `API/JSScript.mm` — SHA-1-validated loader
- `jsc.cpp:1439-1502` — cache read/write shell code

**WebAssembly**
- `wasm/WasmParser.h` — `ParserBase` checked readers
- `wasm/WasmSectionParser.cpp` / `.h` — per-section counts/caps
- `wasm/WasmStreamingParser.cpp` / `.h` — 1 GiB module cap, section staging
- `wasm/WasmFunctionParser.h` — function-body/local parsing
- `wasm/WasmNameSectionParser.cpp`, `WasmBranchHintsSectionParser.cpp`, `WasmSourceMappingURLSectionParser.cpp` — custom sections (non-fatal)
- `wasm/WasmLimits.h` — all sanity constants
- `wasm/WasmFormat.cpp` — `Segment::tryCreate`
- `wasm/WasmMemory.cpp`, `wasm/WasmTable.cpp` / `.h` — instantiation guards
- `runtime/PageCount.h`, `runtime/BufferMemoryHandle.cpp` / `.h` — memory budgets

**Runtime buffers & parsing**
- `runtime/ArrayBuffer.cpp` / `.h` — `CheckedSize` guards, resizable/shared paths
- `runtime/ArrayBufferView.h` / `.cpp` — `verifySubRangeLength`, range ops
- `runtime/JSArrayBufferView.cpp` / `.h` — construction context, Gigacage pointer
- `runtime/JSDataViewPrototype.cpp`, `runtime/JSDataView.cpp` / `.h` — per-access bounds
- `runtime/GenericTypedArrayViewInlines.h`, `runtime/JSGenericTypedArrayViewInlines.h` — view creation/copy guards
- `runtime/JSGenericTypedArrayViewConstructor.cpp`, `JSGenericTypedArrayViewPrototype.cpp` — base64/hex typed-array APIs
- `runtime/JSBigInt.cpp` / `.h` — string parsing with 1-Mbit cap
- `runtime/JSONObject.cpp`, `runtime/LiteralParser.cpp` / `.h` — JSON parse/stringify
- `parser/Lexer.cpp` / `.h` — source lexing bounds

**Custom additions**
- `corpse/CorpseByteParser.cpp` / `.h` — bounds-checked ULEB/C-string cursor
- `corpse/CorpseExportsTrie.cpp`, `corpse/tests/CorpseExportsTrieTest.cpp` — trie walk + adversarial tests
- `corpse/CorpseSymbol.cpp` — Mach-O load commands, sanity caps, read budget
- `corpse/CorpseMemory.cpp` — checked `mach_vm_remap_new` wrapper
- `corpse/CorpseSnapshot.cpp`, `corpse/CorpseClient.cpp` — no binary parsing
- `lol/` — experimental JIT (no untrusted input)
- `mya/mya.cpp` — REPL over Corpse (text input, `strtol`-validated)
- `testmem/testmem.cpp` — RSS tool (trusted file input; one unchecked `fread` path)
- `fuzzilli/Fuzzilli.cpp` — REPRL fuzzing harness

**WTF (supporting primitives, `Source/WTF/wtf/`)**
- `LEBDecoder.h` — LEB128 decode with overflow/truncation/canonical checks
- `Vector.h` — `VectorBufferBase::allocateBuffer`, `growImpl`, `append`, overflow handlers
- `OverflowHandler.h` — `CrashOnOverflow` (release crash) vs `UnsafeVectorOverflow` (debug-only)
- `CheckedArithmetic.h` — `Checked`/`CheckedSize` overflow-flagged arithmetic
- `text/Base64.cpp` / `.h` — `base64DecodeInternal`, `fromBase64Impl`, `maxLengthFromBase64` (simdutf-backed)
- `text/StringImpl.h` — `MaxLength = INT32_MAX` string-length cap

---

## 10. WTF primitives: actual implementations

Audited directly from `Source/WTF/wtf`. These are the shared mechanisms behind
every guard cited in §2–§6.

### 10.1 LEB128 decoding (`wtf/LEBDecoder.h`)

Span-based; every entry point is `[[nodiscard]] bool` and takes the cursor by
reference. Size caps:

```cpp
template<typename T>
constexpr size_t maxByteLength()
{
    constexpr size_t numBits = sizeof(T) * CHAR_BIT;
    return (numBits - 1) / 7 + 1;   // 5 for 32-bit, 10 for 64-bit
}

template<typename T>
constexpr unsigned lastByteMask()
{
    constexpr size_t numBits = sizeof(T) * CHAR_BIT;
    static_assert(numBits % 7);
    return ~((1U << (numBits % 7)) - 1);   // bits the final byte may not set
}
```

**Unsigned decode** — bounds, truncation, and overflow all checked:

```cpp
template<typename T>
[[nodiscard]] inline bool decodeUInt(std::span<const uint8_t> bytes, size_t& offset, T& result)
{
    static_assert(std::is_unsigned_v<T>);
    if (bytes.size() <= offset)
        return false;                                       // cursor at/past end
    result = 0;
    unsigned shift = 0;
    size_t last = std::min(maxByteLength<T>(), bytes.size() - offset) - 1;
    for (unsigned i = 0; true; ++i) {
        uint8_t byte = bytes[offset++];
        result |= static_cast<T>(byte & 0x7f) << shift;
        shift += 7;
        if (!(byte & 0x80))
            return !(((maxByteLength<T>() - 1) == i && (byte & lastByteMask<T>())));
                // ^ overflow: continuation-free final byte of a MAX-length
                //   encoding must not set bits above the type's width
        if (i == last)
            return false;                // truncated (span ran out) or overlong encoding
    }
}
```

- `bytes.size() - offset` is safe: the `size() <= offset` guard runs first.
- `last` clamps the loop to both the type cap *and* the bytes actually present —
  the decoder can never read past the span regardless of a forged length.
- Two distinct rejections: **overflow** (value doesn't fit the type, final byte
  sets high bits) and **overlong/truncated** (continuation bytes persist at the
  cap or the span ends).

**Signed decode** adds **canonical sign-extension** validation on the final byte
of a max-length encoding (`decodeInt`, same file):

```cpp
if ((maxByteLength<T>() - 1) == i) {
    if (!(byte & 0x40)) {
        // non-sign-extended positive: remaining bits must be zero
        // (int32: final byte must be < 0b00000111)
        if (byte & (lastByteMask<T>() >> 1))
            return false;
    } else {
        // sign-extended negative: no zero bits below the top sign bit
        // (int32: final byte 0b01111XXX with bits [3..5] = 0; e.g. 0b01000111 invalid)
        if (static_cast<uint8_t>(~(byte | 0x80)) & (lastByteMask<T>() >> 1))
            return false;
    }
}
...
const size_t numBits = sizeof(T) * CHAR_BIT;
if (shift < numBits && (byte & 0x40))
    result = static_cast<T>(static_cast<UnsignedT>(result) | (static_cast<UnsignedT>(-1) << shift));
```

This rejects non-canonical encodings (e.g. a 2-byte encoding of a value that
fits in 1 byte with padding), so each value has exactly one valid encoding.

**Trusted-stream variants** (`decodeUIntOrCrash` / `decodeIntOrCrash`):

```cpp
// For streams this process encoded itself, where a malformed number is a bug
// rather than input.
template<typename T>
inline T decodeUIntOrCrash(std::span<const uint8_t> bytes, size_t& offset)
{
    T result = 0;
    bool success = decodeUInt<T>(bytes, offset, result);
    RELEASE_ASSERT(success);
    return result;
}
```

Usage split (verified by grep): the `...OrCrash` variants are used only by
**DFG/FTL OSR-exit and variable-event streams**
(`dfg/DFGOSRExit.cpp`, `dfg/DFGOSREntry.cpp`, `dfg/DFGVariableEventStream.cpp`,
`dfg/DFGOSRExitBase.cpp`, `ftl/FTLOSRExit.cpp`) and
`wasm/WasmIPIntSlowPaths.cpp` — streams the process encoded itself, where
malformed data is an internal bug. The **fallible** variants are used by all
untrusted-input paths: `wasm/WasmParser.h`, `wasm/WasmStreamingParser.cpp`,
and `corpse/CorpseByteParser.cpp`.

**Failure semantics:** on `false` the offset has already advanced, but every
call site treats the `false` as a hard parse failure and never reads `result`,
so partial consumption is harmless.

### 10.2 Vector internals (`wtf/Vector.h`)

Template (`wtf/Forward.h:168`):

```cpp
template<typename T, size_t inlineCapacity = 0, typename OverflowHandler = CrashOnOverflow,
         size_t minCapacity = 16, typename Malloc = VectorBufferMalloc> class Vector;
```

**Overflow handlers** — the two policies JSC mixes:

```cpp
// wtf/OverflowHandler.h:53 — the DEFAULT
class CrashOnOverflow {
public:
    SUPPRESS_NODELETE static NO_RETURN_DUE_TO_CRASH void LEGACY_NODELETE overflowed()
    {
        crash();                    // CRASH() — a hard, release-mode crash
    }
    ...
};

// wtf/Vector.h:626 — used by CachedInstructionStream (see §8.8)
struct UnsafeVectorOverflow {
    static NO_RETURN_DUE_TO_ASSERT_WITH_SECURITY_IMPLICATION void overflowed()
    {
        ASSERT_NOT_REACHED_WITH_SECURITY_IMPLICATION();   // DEBUG ONLY — gone in release
    }
};
```

**Hard capacity cap, checked before the size multiply** —
`VectorBufferBase::allocateBuffer` (`Vector.h:212, 221-247`):

```cpp
constexpr inline bool isValidCapacityForVector(size_t capacity)
{ return capacity <= (std::numeric_limits<unsigned>::max() >> 1) / sizeof(T); }
                                                                          // ~2^31 / sizeof(T)

template<FailureAction action>
bool allocateBuffer(size_t newCapacity)
{
    crashIfBorrowed();
    ASSERT(newCapacity);
    if (!isValidCapacityForVector<T>(newCapacity)) {          // checked BEFORE the multiply
        if constexpr (action == FailureAction::Crash)
            CRASH();
        else
            return false;
    }
    size_t sizeToAllocate = newCapacity * sizeof(T);          // now cannot overflow
    T* newBuffer = nullptr;
    if constexpr (action == FailureAction::Crash)
        newBuffer = static_cast<T*>(Malloc::malloc(sizeToAllocate));
    else {
        newBuffer = static_cast<T*>(Malloc::tryMalloc(sizeToAllocate));  // fallible path
        if (!newBuffer) [[unlikely]]
            return false;
    }
    ...
}
```

This is why a hostile `m_size`/`m_length` from the bytecode cache cannot produce
a *wrapping allocation*: even without release bounds checks on the source
buffer, the allocation itself is capped and OOM-detectable.

**Bounds-checked indexing** — `at()` backs `operator[]` (`Vector.h:816-826`):

```cpp
[[nodiscard]] T& at(size_t i) LIFETIME_BOUND
{
    if (i >= size()) [[unlikely]]
        OverflowHandler::overflowed();          // CrashOnOverflow -> CRASH() in release
    return Base::buffer()[i];
}
```

**Wrap-checked append** — `append(std::span)` (`Vector.h:1513-1545`):

```cpp
size_t newSize = m_size + dataSize;
if (newSize > capacity()) {
    dataPtr = expandCapacity<action>(newSize, dataPtr);
    ...
}
if (newSize < m_size) {                 // explicit post-add wrap detection
    if constexpr (action == FailureAction::Crash)
        CRASH();
    else
        return false;
}
```

**32-bit truncation guard in capacity growth** — `growCapacityBy`
(`Vector.h:1465-1477`):

```cpp
unsigned increment32 = static_cast<unsigned>(increment);
unsigned capacity32 = static_cast<unsigned>(capacity());
unsigned newCapacity = increment32 + capacity32;
if (increment32 < increment || newCapacity < capacity32) {   // truncation or wrap
    if constexpr (action == FailureAction::Crash)
        CRASH();
    else
        return false;
}
```

**Crash vs. report API split** (`Vector.h:871-876, 1359-1377, 1424-1447`):
`grow`/`reserveCapacity` use `FailureAction::Crash`; `tryGrow`/`tryReserveCapacity`
use `FailureAction::Report` → `tryMalloc` + `false` on OOM. `growImpl` begins
with `RELEASE_ASSERT_WITH_SECURITY_IMPLICATION(size >= m_size)` (no shrinking
via grow). `unsafeAppendWithoutCapacityCheck` (`:1549`) is the audited escape
hatch, guarded only in debug:
`ASSERT_WITH_SECURITY_IMPLICATION((Checked<size_t>(size()) + dataSize) <= capacity())`.
Under ASan, inline buffers get `__sanitizer_annotate_contiguous_container`
redzone annotations (`asanSetInitialBufferSizeTo` et al.).

**Net effect for JSC's parsers:** every `VectorContainer(m_size)` /
`tryReserveCapacity(count)` / `output.grow(bound)` call site in §2–§6 inherits
these guarantees — the allocation can neither wrap nor silently exceed
~2³¹ elements — while *source-buffer* bounds (reading `m_size` elements out of
an mmap'd cache file) remain each caller's own responsibility, which is exactly
the asymmetry flagged in §8.1.

### 10.3 Base64 (`wtf/text/Base64.cpp`)

**`base64DecodeInternal`** (`:208-287`) — backs `base64Decode` /
`base64DecodeToString` (the `atob` path):

```cpp
template<typename T, typename VectorType = Vector<uint8_t, 0, CrashOnOverflow, 16, VectorBufferMalloc>>
static std::optional<VectorType> base64DecodeInternal(std::span<const T> inputDataBuffer, OptionSet<Base64DecodeOption> options)
{
    if (!inputDataBuffer.size())
        return VectorType { };
    ...
    VectorType destination(inputDataBuffer.size());   // output sized at INPUT length

    unsigned equalsSignCount = 0;
    unsigned destinationLength = 0;
    for (unsigned idx = 0; idx < inputDataBuffer.size(); ++idx) {
        unsigned ch = inputDataBuffer[idx];
        if (ch == '=') {
            ++equalsSignCount;
            if (validatePadding && equalsSignCount > 2)          // > 2 padding chars
                return std::nullopt;
        } else {
            char decodedCharacter = ch < decodeMapSize ? decodeMap[ch] : nonAlphabet;
            if (decodedCharacter != nonAlphabet) {
                if (equalsSignCount)                             // data after padding
                    return std::nullopt;
                destination[destinationLength++] = decodedCharacter;   // in-bounds: <= input length
            } else if (!ignoreWhitespace || !isASCIIWhitespace(ch))
                return std::nullopt;                             // invalid character
        }
    }
    ...
    if (validatePadding && equalsSignCount && (destinationLength + equalsSignCount) % 4)
        return std::nullopt;                                     // bad padding placement
    if ((destinationLength % 4) == 1)
        return std::nullopt;                                     // "n*4 + [0,2,3]" rule

    // 4-byte to 3-byte conversion, in place
    destinationLength -= (destinationLength + 3) / 4;
    ...
    // 3-2-1 repack loop, then:
    if (destinationLength < destination.size())
        destination.shrink(destinationLength);                   // shrink to actual output
    return destination;
}
```

Why sizing the output at the *input* length is overflow-proof: decoded output is
always **shorter** than encoded input (4 chars → 3 bytes; a trailing 2- or 3-char
group yields 1–2 bytes), so no multiplication of the input length occurs at all
— there is no size estimate to overflow. Every index write is
`destinationLength++` against a buffer of `input.size()`, so writes are
structurally in-bounds; validation failures return `std::nullopt` (a JS
`InvalidCharacterError`/syntax error upstream), never a partial buffer.
`base64DecodeToString` (`:303-308`) instantiates the same routine with
`Vector<Latin1Character, 0, CrashOnOverflow, 16, StringImplMalloc>`.

**`maxLengthFromBase64`** (`:371-376`) — the bound used by
`Uint8Array.fromBase64` (§5.2):

```cpp
size_t maxLengthFromBase64(StringView string)
{
    if (string.is8Bit())
        return simdutf::maximal_binary_length_from_base64(byteCast<char>(string.span8()));
    return simdutf::maximal_binary_length_from_base64(string.span16());
}
```

An **exact** upper bound computed by simdutf from the actual characters
(whitespace and padding considered), not a crude `len * 3 / 4` estimate.

**`fromBase64Impl`** (`:339-362`) — the TC39 `Uint8Array.fromBase64` /
`setFromBase64` path:

```cpp
static std::tuple<FromBase64ShouldThrowError, size_t, size_t> fromBase64Impl(
    std::span<const CharacterType> span, std::span<uint8_t> output,
    Alphabet alphabet, LastChunkHandling lastChunkHandling, OutputSizeIsMaxLength outputSizeIsMaxLength)
{
    // Spec step 3: maxLength == 0 returns before looking at a single character,
    // so even invalid input is accepted.
    if (outputSizeIsMaxLength == OutputSizeIsMaxLength::Yes && output.empty())
        return { FromBase64ShouldThrowError::No, 0, 0 };
    ...
    auto [result, outputLength] = simdutf::base64_to_binary_safe(
        simdutfSpan, output, toSIMDUTFDecodeOptions(alphabet),
        toSIMDUTFLastChunkHandling(lastChunkHandling), decodeUpToBadChar);
    switch (result.error) {
    case simdutf::error_code::OUTPUT_BUFFER_TOO_SMALL:
    case simdutf::error_code::SUCCESS:
        return { FromBase64ShouldThrowError::No, result.count, outputLength };
    default:
        return { FromBase64ShouldThrowError::Yes, result.count, outputLength };
    }
}
```

`simdutf::base64_to_binary_safe` never writes past `output` — when the caller's
span is too small it reports `OUTPUT_BUFFER_TOO_SMALL` with the *actual* bytes
written (`outputLength`), which is why the JSC call sites (§5.2) must clamp the
final copy to `writeLength`: an over-large `maxLengthFromBase64` can only mean
unused tail capacity, and `OutputSizeIsMaxLength::Yes` treats the span size as a
hard limit. `decodeUpToBadChar = true` means decoding proceeds up to the first
invalid character and reports its position in `result.count`, rather than
failing the whole input.

### 10.4 String length cap and checked arithmetic

**`StringImpl` maximum length** (`wtf/text/StringImpl.h:151, 212`):

```cpp
static constexpr unsigned MaxLength = std::numeric_limits<int32_t>::max();   // ~2 GiB characters
```

Every WTF string — and therefore every source string the Lexer walks (§5.3) and
every JSON/BigInt input string (§4, §5.1) — is capped at `INT32_MAX`
characters. This closes the earlier nit about the Lexer's 32-bit token offsets
(`Lexer.h:141`): a truncation to `int` cannot lose bits for any string that can
actually exist.

**`CheckedArithmetic.h`** — the `Checked`/`CheckedSize` types behind the §6
guards: overflow sets an internal flag (`hasOverflowed()`) instead of wrapping,
so callers can batch several operations and test once
(`sizeInBytes.hasOverflowed() || sizeInBytes.value() > MAX_ARRAY_BUFFER_SIZE`).
`Checked<size_t, CrashOnOverflow>` (the form used in
`ArrayBufferView.cpp:45-57`, `JSArrayBufferView.h:200-206`) crashes on an
implicit conversion of an overflowed value, making "used a wrapped size"
impossible rather than merely unlikely. The wasm parser's
`Checked<unsigned, RecordOverflow>` (`WasmSectionParser.cpp:984-995`) and the
streaming parser's `m_totalSize.hasOverflowed()` (`WasmStreamingParser.cpp:309`)
are the same mechanism on the parse side.

Together these three primitives — `LEBDecoder` (no uncanonical or overflowing
varint can pass), `Vector` (no allocation can wrap or exceed its hard cap;
default policy crashes in release, `try*` variants report), and
`Base64`/`Checked` (estimates are exact or overflow-flagged) — are what make
the "caps before allocation, fallible allocation, fail-closed" discipline of
§7 mechanically enforceable rather than convention.
