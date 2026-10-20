# JSC Garbage Collector & Memory Management — Low-Level Architectural Audit

> Deep architectural audit of `Source/JavaScriptCore/heap/` (~180 files), grounded
> in the actual source of this tree. Every class, method, and line citation was
> read and spot-verified directly.
>
> **Companion document:** [JSC-input-parsing-analysis.md](JSC-input-parsing-analysis.md)
> (parsing/serialization/buffer boundaries). This document covers the runtime's
> *memory lifecycle* instead: allocation → marking → conservative root capture →
> sweeping/reclamation.

> **⚠ Tree-divergence note (important):** this checkout contains a 2024–2026 era
> "multi-heap Collector" refactor and several local additions that differ from
> stock upstream WebKit. Verified divergences are called out inline; the most
> consequential ones:
> - GC driver is `Collector` + `CollectorPhase` (not `Heap::collectContinuously`).
> - `AllocationFailureMode` enumerators are `Assert`/`ReturnNull` (not `Crash`/`NullReturn`).
> - There is **no `wtf/GCMutatorFence.h`** — the mutator fence is `Heap::mutatorFence()`.
> - No `Heap::allocateCell`; entry points are free templates in `runtime/JSCellInlines.h`.
> - New machinery: `PreciseSubspace`, "lower-tier precise" cells
>   (`IsoSubspace::tryAllocateLowerTierPrecise`), `GCClient::IsoSubspace` with an
>   embedded `LocalAllocator`, thread-safe `BlockDirectoryBits` with stealable empty blocks.
> - No `MarkedBlock::sweepRecursively`, no `m_toBeDestroyed`, no `PrimitiveCellSpace`,
>   no handle ref-counting on `MarkedBlock::Handle`.

---

## Table of contents

1. [Subsystem map & data-flow overview](#1-subsystem-map--data-flow-overview)
2. [Object allocation mechanics](#2-object-allocation-mechanics)
3. [The marking phase](#3-the-marking-phase)
4. [Conservative stack & register scanning](#4-conservative-stack--register-scanning)
5. [Sweeping & reclamation](#5-sweeping--reclamation)
6. [Safety properties, invariants & known weaknesses](#6-safety-properties-invariants--known-weaknesses)
7. [Core call graphs](#7-core-call-graphs)
8. [File index](#8-file-index)

---

## 1. Subsystem map & data-flow overview

| Concern | Core files |
|---|---|
| Cycle driver / phases | `Collector.{h,cpp}`, `CollectorPhase.{h,cpp}`, `GCConductor.{h,cpp}`, `MutatorScheduler*` |
| Subspaces & allocators | `Subspace*`, `CompleteSubspace*`, `IsoSubspace*`, `PreciseSubspace*`, `Allocator*`, `LocalAllocator*`, `FreeList*` |
| Blocks & space | `MarkedBlock*`, `BlockDirectory*`, `BlockDirectoryBits.h`, `MarkedSpace*`, `PreciseAllocation*` |
| Marking | `MarkingConstraint*`, `SlotVisitor*`, `AbstractSlotVisitor*`, `MarkStack*`, `GCSegmentedArray*`, `VerifierSlotVisitor*` |
| Write barriers | `runtime/WriteBarrier.h` + `WriteBarrierInlines.h`, `heap/WriteBarrierSupport.*`, `Heap::writeBarrier`/`mutatorFence` (`HeapInlines.h`) |
| Conservative roots | `ConservativeRoots.*`, `MachineStackMarker.*`, `RegisterState.h`, `TinyBloomFilter.h`, `MarkedBlockSet.h`, `JITStubRoutineSet*`, `CodeBlockSet*` |
| Sweeping / reclamation | `IncrementalSweeper.*`, `SweepingScope.h`, `MarkedBlockInlines.h` (`specializedSweep`), `WeakBlock*`/`WeakSet*`, `Heap::pruneDeadReferences` |
| Memory back ends | `AlignedMemoryAllocator.h`, `FastMallocAlignedMemoryAllocator*`, `GigacageAlignedMemoryAllocator*`, `StructureAlignedMemoryAllocator*` |
| Scopes & protocol | `AllocatingScope.h`, `CollectingScope.h`, `DeferGC*`, `HeapObserver.h`, `GCRequest.h` |

**One cycle, end to end:**

```
requestCollection (mutator takes "the conn")
  → Begin        (world stopped): versions flipped, mutator fenced, visitors set up
  → Fixpoint     (world stopped): constraint solve — roots, then outgrowths; drain marks
  → Concurrent   (world running): collector thread drains passively; mutator helps at
                                  allocation slow paths; write barriers feed mutator mark stack
  → Reloop → Fixpoint … until convergence
  → End          (world stopped): weak reaping, code cleanup, sweep scheduling
  → IncrementalSweeper / lazy sweep-to-freelist on allocation  (destruction + free-list rebuild)
```

Mutator pause policy per phase (`CollectorPhase.cpp:33-49`,
`worldShouldBeSuspended`): world **stopped** during `Begin`, `Fixpoint`, `Reloop`,
`End`; world **running** during `NotRunning` and `Concurrent`.

---

## 2. Object allocation mechanics

### 2.1 Entry point & failure modes

There is no `Heap::allocateCell` in this tree. All cell allocation funnels
through free templates in `runtime/JSCellInlines.h:151-191`:

```cpp
template<typename T, AllocationFailureMode failureMode>
ALWAYS_INLINE void* tryAllocateCellHelper(VM& vm, size_t size, GCDeferralContext* deferralContext)
{
    ASSERT(deferralContext || vm.heap.isDeferred() || !AssertNoGC::isInEffectOnCurrentThread());
    ASSERT(size >= sizeof(T));
    JSCell* result = static_cast<JSCell*>(subspaceFor<T>(vm)->allocate(
        vm, WTF::roundUpToMultipleOf<T::atomSize>(size), deferralContext, failureMode));
    if constexpr (failureMode == AllocationFailureMode::ReturnNull) {
        if (!result)
            return nullptr;
    }
    ...
    result->clearStructure();
    return result;
}

template<typename T> void* allocateCell(VM& vm, size_t size)
{ return tryAllocateCellHelper<T, AllocationFailureMode::Assert>(vm, size, nullptr); }
template<typename T> void* tryAllocateCell(VM& vm, size_t size)
{ return tryAllocateCellHelper<T, AllocationFailureMode::ReturnNull>(vm, size, nullptr); }
```

Every cell class exposes a static `subspaceFor<SubspaceAccess mode>(VM&)`
(`runtime/JSCell.h:318-328`), returning e.g. a `GCClient::IsoSubspace*`.
`SubspaceAccess::Concurrently` must not lazily create a subspace (returns null).

**Failure modes** — `heap/AllocationFailureMode.h:30-33`:

```cpp
enum class AllocationFailureMode {
    Assert,      // OOM is a bug: crash (via RELEASE_ASSERT_RESOURCE_AVAILABLE, crash code 31)
    ReturnNull   // fallible allocation: propagate nullptr to the caller
};
```

The slow paths enforce this at the true fallback (`LocalAllocator.cpp:166-169`):

```cpp
MarkedBlock::Handle* block = m_directory->tryAllocateBlock(heap);
if (!block) [[unlikely]] {
    RELEASE_ASSERT_RESOURCE_AVAILABLE(failureMode != AllocationFailureMode::Assert,
        MemoryExhaustion, "Crash intentionally because memory is exhausted.");
    return nullptr;
}
```

**Mutator state machine** — `heap/MutatorState.h:32-44`:

```cpp
enum class MutatorState : uint8_t {
    Running,    // not inside a Heap slow path
    Allocating, // in an allocation slow path
    Sweeping,   // mutator is sweeping
    Collecting  // mutator is collecting
};
```

Stored as `Heap::m_mutatorState`; **not** checked on the fast path. It gates GC
reentrancy: `Heap::collectIfNecessaryOrDefer` (`Heap.cpp:2238-2254`) returns
early when `Sweeping`/`Collecting`, proceeds when `Running`/`Allocating`.
Slow paths enter `AllocatingScope` (`AllocatingScope.h:32-49`, RAII with
`RELEASE_ASSERT` on both state transitions) so nested collection requests know
the mutator is inside a slow path. Deferral (`GCDeferralContext.h:36-49`) only
*records* the need (`m_shouldGC = true`); the GC happens at
`decrementDeferralDepthAndGCIfNeeded` (`HeapInlines.h:180-209`).

### 2.2 Subspace hierarchy

`Subspace` (`heap/Subspace.h:39-119`) with `SubspaceKind { CompleteSubspace,
IsoSubspace, PreciseSubspace }` — owns a `HeapCellType` (sweep/destructor
policy), an `AlignedMemoryAllocator`, block directories, and a sentinel list of
`PreciseAllocation`s. Three concrete kinds:

**`CompleteSubspace`** — the multi-size-class subspace (`auxiliarySpace`,
`cellSpace`, `destructibleObjectSpace`, `primitiveGigacageAuxiliarySpace`, …).
Holds `std::array<Allocator, MarkedSpace::numSizeClasses>`; fast path
(`CompleteSubspaceInlines.h:33-41`):

```cpp
ALWAYS_INLINE void* CompleteSubspace::allocate(VM& vm, size_t cellSize, GCDeferralContext* deferralContext, AllocationFailureMode failureMode)
{
    if (Allocator allocator = allocatorFor(cellSize, AllocatorForMode::AllocatorIfExists))
        return allocator.allocate(vm.heap, allocator.cellSize(), deferralContext, failureMode);
    return allocateSlow(vm, cellSize, deferralContext, failureMode);
}
```

Sizes above `MarkedSpace::largeCutoff` (half a block payload, `MarkedSpace.h:65`)
fall to `tryAllocateSlow` (`CompleteSubspace.cpp:113-144`) →
`PreciseAllocation::tryCreate`. Butterflies grow in place via
`reallocatePreciseAllocationNonVirtual` (`:146-200`) →
`PreciseAllocation::tryReallocate` (realloc + `memmove`).

**`IsoSubspace`** — one cell type, one fixed size, one `BlockDirectory`
(`IsoSubspace.cpp:39-53`). "Iso" buys type-pure iteration and O(1) membership
sets (`IsoCellSet`: one bit per cell, documented in `IsoCellSet.h:43-46` as
"a 0.8% increase in object size"). The `GCClient::IsoSubspace` proxy
(`IsoSubspace.h:74-99`) embeds a `LocalAllocator` so JIT/client code allocates
without a server-side `Subspace*`:

```cpp
ALWAYS_INLINE Allocator IsoSubspace::allocatorFor(size_t size, AllocatorForMode)
{
    RELEASE_ASSERT(size <= cellSize());
    return Allocator(&m_localAllocator);
}
```

**Lower-tier precise fallback (this tree only):** when an IsoSubspace can't get
a block, `tryAllocateLowerTierPrecise` (`IsoSubspace.cpp:81-105`) hands out up
to `MarkedBlock::maxNumberOfLowerTierPreciseCells == 8` recycled
`PreciseAllocation` headers before a new block is attempted.

**`PreciseSubspace`** (`PreciseSubspace.h:32-47`, `.cpp:62-85`) — large,
rarely-allocated, variable-size objects with **no** `LocalAllocator` at all
(`didResizeBits`/`didRemoveBlock` are `UNREACHABLE_FOR_PLATFORM`). Used for
`JSWebAssemblyInstance`. Requires `ReturnNull`:

```cpp
ASSERT_WITH_MESSAGE(failureMode == AllocationFailureMode::ReturnNull,
    "PreciseSubspace is meant for large objects so it should always be able to fail.");
```

### 2.3 `Allocator` → `LocalAllocator` → `FreeList`: the fast path

`Allocator` (`Allocator.h:39-59`) is a one-word handle wrapping a
`LocalAllocator*`. The hot allocation path is three instructions deep:

```cpp
// LocalAllocatorInlines.h:33-43
ALWAYS_INLINE void* LocalAllocator::allocate(JSC::Heap& heap, size_t cellSize, GCDeferralContext* deferralContext, AllocationFailureMode failureMode)
{
    VM& vm = heap.vm();
    if constexpr (validateDFGDoesGC) vm.verifyCanGC();
    return m_freeList.allocateWithCellSize(
        [&]() ALWAYS_INLINE_LAMBDA {
            sanitizeStackForVM(vm);
            return static_cast<HeapCell*>(allocateSlowCase(heap, cellSize, deferralContext, failureMode));
        }, cellSize);
}

// FreeListInlines.h:35-54 — bump-allocate within the current free interval
ALWAYS_INLINE HeapCell* FreeList::allocateWithCellSize(NOESCAPE const Invocable<void()> auto& slowPath, size_t cellSize)
{
    if (m_intervalStart < m_intervalEnd) [[likely]] {
        char* result = m_intervalStart;
        m_intervalStart += cellSize;
        return std::bit_cast<HeapCell*>(result);
    }
    FreeCell* cell = nextInterval();
    if (isSentinel(cell)) [[unlikely]]
        return slowPath();
    FreeCell::advance(m_secret, m_nextInterval, m_intervalStart, m_intervalEnd);
    ...
}
```

**The free list is secret-scrambled interval nodes** (`FreeList.h:39-80`) — not
a pointer chain. Each dead run of cells stores XOR-encoded *(relative offset to
next interval, run length)*:

```cpp
struct FreeCell {
    static ALWAYS_INLINE uint64_t scramble(int32_t offsetToNext, uint32_t lengthInBytes, uint64_t secret)
    { return (static_cast<uint64_t>(lengthInBytes) << 32 | offsetToNext) ^ secret; }
    ...
    ALWAYS_INLINE void makeLast(uint32_t lengthInBytes, uint64_t secret)
    { scrambledBits = scramble(1, lengthInBytes, secret); }  // LSB = sentinel
    ALWAYS_INLINE void setNext(FreeCell* next, uint32_t lengthInBytes, uint64_t secret)
    { scrambledBits = scramble((next - this) * sizeof(FreeCell), lengthInBytes, secret); }
    uint64_t preservedBitsForCrashAnalysis;
    uint64_t scrambledBits;
};
```

The per-sweep random `secret` (`vm.heapRandom().getUint64()`,
`MarkedBlockInlines.h:267`) randomizes the freelist against heap-spray
guessing; intervals let one node describe a whole dead run, enabling bump
allocation inside it. One `FreeList` per `LocalAllocator` holds the current
interval (`m_intervalStart`/`m_intervalEnd`) + next-interval head + sentinel
(`isSentinel` = low bit set).

### 2.4 Slow path order & block exhaustion

`LocalAllocator::allocateSlowCase` (`LocalAllocator.cpp:130-174`) — the exact
fallback order:

```cpp
void* LocalAllocator::allocateSlowCase(JSC::Heap& heap, size_t cellSize, GCDeferralContext* deferralContext, AllocationFailureMode failureMode)
{
    doTestCollectionsIfNeeded(heap, deferralContext);       // test hook
    ...
    heap.didAllocate(m_freeList.originalSize());            // charge bytes; may schedule GC
    didConsumeFreeList();                                   // directory bit: Allocated
    AllocatingScope helpingHeap(heap);                      // MutatorState::Allocating
    heap.collectIfNecessaryOrDefer(deferralContext);        // run/help GC first
    if (m_currentBlock) [[unlikely]] return allocate(...);  // GC callback reentered this directory
    void* result = tryAllocateWithoutCollecting(cellSize);  // (1) other partially-used blocks
    if (result) [[likely]] return result;
    Subspace* subspace = m_directory->m_subspace;
    if (subspace->isIsoSubspace()) {                        // (2) lower-tier precise (this tree)
        if (void* result = static_cast<IsoSubspace*>(subspace)->tryAllocateLowerTierPrecise(cellSize))
            return result;
    }
    MarkedBlock::Handle* block = m_directory->tryAllocateBlock(heap);  // (3) brand-new block
    if (!block) [[unlikely]] {
        RELEASE_ASSERT_RESOURCE_AVAILABLE(failureMode != AllocationFailureMode::Assert,
            MemoryExhaustion, "Crash intentionally because memory is exhausted.");
        return nullptr;                                     // (4) OOM (ReturnNull only)
    }
    m_directory->addBlock(block);
    result = allocateIn(block, cellSize);
    ...
}
```

Block discovery & reuse:
- `tryAllocateWithoutCollecting` (`:185-235`) loops
  `m_directory->findBlockForAllocation(*this)` (`BlockDirectory.cpp:120-145`:
  scans `canAllocateBits & ~inUseBits` from the allocator's own
  `m_allocationCursor`, `claimInUse` as a per-block lock, prefetch). Then, if
  `Options::stealEmptyBlocksFromOtherAllocators()`, it steals a whole empty
  block from **any directory sharing the same `AlignedMemoryAllocator`** via
  `findEmptyBlockToSteal()` (`AlignedMemoryAllocator.cpp:72-84`) — this is the
  cross-subspace block-borrowing mechanism.
- `tryAllocateIn` (`:244-271`) **builds the free list lazily on first
  allocation from a block**: `block->sweep(&m_freeList)`; if the list comes out
  empty (full block), `block->unsweepWithNoNewlyAllocated()` and try the next.

### 2.5 `MarkedBlock`: geometry & header

```cpp
// MarkedBlock.h:77-96
static constexpr size_t atomSize = 16;                              // bytes
static constexpr size_t blockSize = std::max(16 * KB, CeilingOnPageSize);
static constexpr size_t blockMask = ~(blockSize - 1);
using AtomNumberType = uint16_t;
static constexpr size_t maxNumberOfLowerTierPreciseCells = 8;       // this tree only
```

The block *is* the allocation: `MarkedBlock::tryCreate` gets
`tryAllocateAlignedMemory(blockSize, blockSize)` and placement-news the header
at offset 0; `blockFor(p)` is a single mask. Per-block state is split:

- `MarkedBlock::Header` (`MarkedBlock.h:264-359`): `m_marks` and
  `m_newlyAllocated` `BitSet<atomsPerBlock>` guarded by heap *versions*
  (`m_markingVersion`, `m_newlyAllocatedVersion`) plus a racy
  `m_biasedMarkCount` for retirement heuristics.
- `BlockDirectoryBits` (`BlockDirectoryBits.h:42-54`) — per-block worklist bits,
  segment-interleaved so a block's bits share a cache line:

```cpp
macro(live, Live, BlockOwned)          /* blocks that exist */
macro(empty, Empty, BlockOwned)        /* no live objects, not free listed */
macro(allocated, Allocated, BlockOwned)/* full of live objects */
macro(canAllocate, CanAllocate, BlockOwned)
macro(destructible, Destructible, BlockOwned)
macro(eden, Eden, BlockOwned)          /* has new objects since last GC */
macro(unswept, Unswept, BlockOwned)    /* candidates for incremental sweeper */
macro(inUse, InUse, Unowned)           /* acts like a per-block lock */
macro(markingNotEmpty, MarkingNotEmpty, Unowned)
macro(markingRetired, MarkingRetired, Unowned)
```

### 2.6 Large objects: `PreciseAllocation`

Cells ≥ `largeCutoff` skip blocks entirely. Recognition is a single bit test —
the cell pointer is deliberately 8-mod-16 aligned (`PreciseAllocation.h:39-185`):

```cpp
// "We can detect when a HeapCell* is a PreciseAllocation because it will have
//  the MarkedBlock::atomSize / 2 bit set."
static constexpr unsigned halfAlignment = MarkedBlock::atomSize / 2;   // 8
static bool isPreciseAllocation(HeapCell* cell)
{ return std::bit_cast<uintptr_t>(cell) & halfAlignment; }
```

`tryCreate` (`PreciseAllocation.cpp:80-111`) allocates via
`tryAllocateMemory` (not the aligned path — it must support `realloc` for
butterfly growth), shifts to odd-half-alignment, and adds a
`cacheLineAdjustment` so a JSObject header + butterfly share one cache line.
Liveness is `Atomic<bool> m_isMarked` + `m_isNewlyAllocated`;
`testAndSetMarked()` avoids the CAS when already marked (`:129-137`).

### 2.7 Memory back ends (Gigacage & friends)

`AlignedMemoryAllocator` (`AlignedMemoryAllocator.h:36-65`) abstracts block
(aligned) vs precise (malloc-like, realloc-able) allocation, and hosts the
cross-directory empty-block steal list. Three implementations, all members of
`Heap` (`Heap.h:1029-1031`):

- **`FastMallocAlignedMemoryAllocator`** — default; also pools pre-warmed MarkedBlocks.
- **`GigacageAlignedMemoryAllocator`** — wraps `Gigacage::tryAlignedMalloc`;
  backs `primitiveGigacageAuxiliarySpace` (typed arrays, strings, butterflies).
  This is where **Gigacage confinement** enters: every backing store of those
  subspaces lives in the Primitive cage so JIT code can mask pointers for OOB
  checks.
- **`StructureAlignedMemoryAllocator`** — reserves an equally-aligned
  power-of-two range (`g_jscConfig.startOfStructureHeap`) so the **top 32 bits
  of every Structure address are constant**, which is what makes 32-bit
  `StructureID`s encodable (`structureIDBase = startOfStructureHeap &
  ~StructureID::structureIDMask`). Its `tryAllocateMemory` returns nullptr and
  `freeMemory`/`tryReallocateMemory` are `RELEASE_ASSERT_NOT_REACHED` —
  Structures cannot be precise allocations, hence `structureSpace` must be a
  fixed-size IsoSubspace.

---

## 3. The marking phase

### 3.1 The "conn": who drives the cycle

`GCConductor` (`GCConductor.h:35-38`) is a nautical-conn token: either the
mutator drives GC incrementally from slow paths, or the collector thread does.
A requesting mutator steals the conn at request time (`Collector.cpp:220-241`):

```cpp
if ((m_lastServedTicket == m_lastGrantedTicket) && !m_threadIsWorking && hasHeap(requester)) {
    dataLogLnIf(CollectorInternal::verbose, "Taking the conn.");
    requester.m_worldState.exchangeOr(Heap::mutatorHasConnBit);
}
m_requests.append(request);
m_lastGrantedTicket++;
// A mutator that has the conn serves the request at its next poll, and otherwise the collector thread does.
if (!anyMutatorHasConnWithLock())
    m_threadCondition->notifyOne(locker);
```

The phase machine (`CollectorPhase.h:41-64`):

```cpp
enum class CollectorPhase : uint8_t {
    NotRunning,  // collector not running. After this state is Begin.
    Begin,       // ... until it first yields to the mutator for marking. After this is Fixpoint.
    Fixpoint,    // do progress with the world stopped: MarkingConstraintSet::executeConvergence.
    Concurrent,  // relying on parallel helpers and incremental mutator work. After: Reloop.
    Reloop,      // ran out of work; prepares for another Fixpoint.
    End          // trying to finish up. After: NotRunning.
};
```

Mutator pause transitions are managed by `changePhase`/`finishChangingPhase`
(`Collector.cpp:698-755`): on suspend, `heap().stopTheMutator()` then
`stopThePeriphery()` (suspends JIT compiler threads, sets
`m_collectorSlotVisitor->setMutatorsAreStopped(true)`); on resume, the reverse,
so no mutator ever runs while the collector believes the world is stopped.
`Heap::stopTheMutator` (`Collector.cpp` path via `Heap.cpp:1391-1455`) CAS-loops
`m_worldState`; if the mutator currently holds heap access it *hands the conn
over* and parks; waiting mutators park in `waitForCollector`
(`ParkingLot::compareAndPark(&m_worldState, oldState | mutatorWaitingBit)`).
The mutator-side poll is `Heap::stopIfNecessary()` (`HeapInlines.h:221-228`),
hit on every allocation slow path — this is where a mutator with the conn
*helps* run the Concurrent phase.

### 3.2 Constraint-based root & outgrowth scanning

All tracing work is registered as `MarkingConstraint`s
(`MarkingConstraint.h:46-104`) with three orthogonal properties:

- `ConstraintConcurrency` — with *other constraints* (all run with world stopped):
  `Sequential | Concurrent`.
- `ConstraintParallelism` — `Sequential | Parallel` across helper threads.
- `ConstraintVolatility` (`ConstraintVolatility.h:32-50`):
  - `SeldomGreyed` — unlikely to produce work; run "at the bitter end".
  - `GreyedByExecution` — re-evaluated whenever the mutator runs: a **root**.
  - `GreyedByMarking` — re-evaluated any time any object is marked: an **outgrowth**.

The core constraints registered per heap (`Heap::createCoreConstraints`,
`Heap.cpp:2394-2645`):

| Abbr | Name | Volatility | Parallel | Purpose |
|---|---|---|---|---|
| `"Cs"` | Conservative Scan | root | — | stack/register conservative roots (§4) |
| `"Msr"` | Misc Small Roots | root | — | misc precise roots |
| `"Sh"` | Strong Handles | root | — | API handles (`Strong`) |
| `"D"` | Debugger | root | — | debugger roots |
| `"Ws"` | Weak Sets | outgrowth | **Parallel** | weak-reachability queries |
| `"O"` | Output | outgrowth | **Parallel** | `visitOutputConstraints` (executables, WeakMap…) |
| `"Pbc"` | Pinball Completions | outgrowth | — | evacuated wasm/async stack slices |
| `"Jw"` | JIT Worklist | outgrowth | — | code being compiled |
| `"Cb"` | CodeBlocks | SeldomGreyed | — | executing/compiling CodeBlocks, deferred to black |
| `"Msm"` | Mark Stack Merging | root | — | merges mutator + race mark stacks |

`MarkingConstraintSet::executeConvergenceImpl` (`MarkingConstraintSet.cpp:103-171`)
implements the fixpoint schedule: iteration 1 drains roots, iteration 2 drains
outgrowths, later iterations order constraints by `isWavefrontAdvancing` +
`workEstimate` (last visit counts via `VisitCounter`), and the set has converged
when an iteration visits nothing. `MarkingConstraintSolver` executes the chosen
order in parallel across helper threads, with `Sequential`-concurrency
constraints deferred to a sequential queue per worker (`:156-258`).

`"Cs"` (the conservative scan, `Heap.cpp:2398-2448`) memoizes per phase version
and asserts the safepoint preconditions — see §4.

### 3.3 Visitors & the mark stack

`SlotVisitor` (`SlotVisitor.h:49`) is `alignas(128)` — "Visitors should not
share cachelines". Each visitor owns two private stacks (`m_collectorStack`,
`m_mutatorStack`, `AbstractSlotVisitor.h:229-230`); the shared pools live on the
`Collector` (`m_sharedCollectorMarkStack`, `m_sharedMutatorMarkStack`,
`m_raceMarkStack`). The mark stack is `MarkStackArray : GCSegmentedArray<const
JSCell*>` — 4 KB segments from a dedicated malloc heap, with `transferTo`,
`donateSomeCellsTo`, and `stealSomeCellsFrom(other, idleThreadCount)` for
work-stealing between markers.

The hot append path (`SlotVisitorInlines.h:50-74`):

```cpp
ALWAYS_INLINE void SlotVisitor::appendUnbarriered(JSCell* cell)
{
    if (!cell) return;
    Dependency dependency;
    if (cell->isPreciseAllocation()) [[unlikely]] { ... }
    else {
        MarkedBlock& block = cell->markedBlock();
        dependency = block.aboutToMark(m_markingVersion, cell);   // loads version w/ fence; resets stale marks
        if (block.isMarked(cell, dependency)) [[likely]] { ... return; }
    }
    appendSlow(cell, dependency);   // -> testAndSetMarked, grey (CellState::PossiblyGrey), push
}
```

Version-guarded mark bits (`MarkedBlock.h:633-671`) are the eden-GC mechanism:

```cpp
inline bool MarkedBlock::isMarked(HeapVersion markingVersion, const void* p)
{
    HeapVersion version;
    Dependency dependency = Dependency::loadAndFence(&header().m_markingVersion, version);
    if (version != markingVersion) [[unlikely]] return false;
    return header().m_marks.concurrentGet(atomNumber(p), dependency);
}
```

`aboutToMark` + `resetStaleMarks` (`MarkedBlock.cpp:284-350`) handles full-GC
version bumps: stale survivor marks are *transferred* into `m_newlyAllocated`
so they count as live without re-marking.

**Graph traversal:** `SlotVisitor::visitChildren` (`SlotVisitor.cpp:368-427`)
sets `CellState::PossiblyBlack` + `WTF::storeLoadFence()`, then dispatches —
hot types by `switch (cell->type())`, everything else through
`cell->methodTable()->visitChildren(...)`. Each class implements
`static void Foo::visitChildren(JSCell*, Visitor&)` + `DEFINE_VISIT_CHILDREN`.

**Weak references** are not traced in `visitChildren`; they are the `"Ws"`
constraint (`Heap.cpp:2524-2533`) running `WeakBlock::specializedVisit`
(`WeakBlock.cpp:131-185`): for each `Live` impl whose cell is unmarked, ask
`weakHandleOwner->isReachableFromOpaqueRoots(...)`; if reachable,
`visitor.appendUnbarriered(jsValue)` — otherwise the impl is left to be reaped.

**Termination** (`SlotVisitor.cpp:589-606`): no active parallel markers *and*
all three stacks (private + both shared) empty. The `VerifierSlotVisitor`
(under `Options::verifyGC()`) keeps its own per-cell mark bitmaps + referrer
stack traces and re-marks everything through the constraints after End; the GC
then asserts the verifier's set ⊆ real set (`Collector::verifyGC`,
`Collector.cpp:997-1016`) — a built-in differential check of marking soundness.

### 3.4 Write barriers

`WriteBarrier<T>::set` (via `WriteBarrierInlines.h`) stores then calls
`Heap::writeBarrier(from, to)` — the fast path is one enum compare
(`HeapInlines.h:97-121`):

```cpp
inline void Heap::writeBarrier(const JSCell* from, JSCell* to)
{
    ...
    if (isWithinThreshold(from->cellState(), barrierThreshold())) [[unlikely]]
        writeBarrierSlowPath(from);
}
```

`barrierThreshold` is normally `blackThreshold` (= 0: only `PossiblyBlack`
sources fire) and `tautologicalThreshold` (all stores fire) while the mutator
must be fenced — flipped by `Heap::setMutatorShouldBeFenced`
(`Heap.cpp:2705-2709`); `beginMarking` turns fencing on.

The slow path greys the source onto the mutator mark stack
(`Heap.cpp:2189-2200` + `addToRememberedSet`, `:1154-1210`):

```cpp
void Heap::writeBarrierSlowPath(const JSCell* from)
{
    if (mutatorShouldBeFenced()) [[unlikely]] {
        WTF::storeLoadFence();
        if (from->cellState() != CellState::PossiblyBlack)
            return;
    }
    addToRememberedSet(from);
}

// addToRememberedSet (fenced variant), simplified:
if (m_mutatorShouldBeFenced) {
    WTF::loadLoadFence();
    if (!isMarked(cell)) {
        RELEASE_ASSERT(m_collectionScope && *m_collectionScope == CollectionScope::Full);
        // Repair the mark/blacken race: try to re-white an unmarked black object.
        if (cell->atomicCompareExchangeCellStateStrong(CellState::PossiblyBlack, CellState::DefinitelyWhite) == CellState::PossiblyBlack) {
            if (isMarked(cell)) cell->setCellState(CellState::PossiblyBlack);
        }
        return;
    }
}
cell->setCellState(CellState::PossiblyGrey);
m_mutatorMarkStack->append(cell);
```

The mutator mark stack is merged only at a safepoint, by the `"Msm"`
constraint (`MarkStackMergingConstraint.cpp:37-77`:
`m_mutatorMarkStack->transferTo(visitor.mutatorMarkStack())`).

**The mutator fence** — there is **no `wtf/GCMutatorFence.h` in this tree**;
the equivalent is `Heap::mutatorFence()` (`HeapInlines.h:123-134`), placed by
every `WriteBarrier` setter after the store:

```cpp
inline void Heap::mutatorFence()
{
    // On X86 a storeStoreFence is a compilerFence.
    if constexpr (isX86()) { WTF::compilerFence(); return; }
    if (mutatorShouldBeFenced()) [[unlikely]]
        WTF::storeStoreFence();
}
```

**Race soundness recap** (the Dijkstra-style "black mutator store" problem):
a marker blackens a cell (`PossiblyBlack` + storeLoad fence) while the mutator
stores into it. The fence-ordered barrier then sees either the new value (marker
re-greys via outgrowth constraints / race stack) or `PossiblyBlack` with the
cell unmarked (the re-white CAS above repairs it during Full GC). Explicit races
can also be reported through `SlotVisitor::didRace(VisitRaceKey)` →
`m_raceMarkStack`, re-merged each Fixpoint.

### 3.5 `CellState`

Per-cell tristate (`CellState.h:31-52`), stored in the cell header:

```cpp
enum class CellState : uint8_t {
    PossiblyBlack  = 0,  // being scanned, finished scanning, or white-in-full-GC
    DefinitelyWhite = 1, // in eden; not marked yet during GC
    PossiblyGrey   = 2   // "sorta... grey - i.e. it will be scanned"
};
static constexpr unsigned blackThreshold = 0;
static constexpr unsigned tautologicalThreshold = 100;
```

### 3.6 Schedulers

`MutatorScheduler` (base, `MutatorScheduler.h:34-73`) answers `timeToStop()` /
`timeToResume()`:

- **`SpaceTimeMutatorScheduler`** — links pause time to space allocated since
  the cycle began: headroom = `concurrentGCMaxHeadroom × max(begin, totalMaxEdenSize())`;
  `mutatorUtilization = 1 − headroomFullness`, clamped to
  `[minimumMutatorUtilization, maximumMutatorUtilization]`.
- **`StochasticSpaceTimeMutatorScheduler`** — probabilistic resume
  (`m_random.get() < resumeProbability`) and measured pause targets.
- **`SynchronousStopTheWorldMutatorScheduler`** — world always stopped while
  GC runs; used when `!Options::useConcurrentGC()` (i.e. concurrent GC off
  *simulated* by policy rather than by a separate code path).

---

## 4. Conservative stack & register scanning

### 4.1 The pipeline

```
Collector::conduct (Collector.cpp:285-320)
  → callWithCurrentThreadState          // capture stack top + callee-saves, prevent tail calls
  → "Cs" constraint (Heap.cpp:2398)     // world stopped, once per phase version
      → Heap::gatherStackRoots          // machine threads + C-loop stack
      → Heap::gatherVMRoots             // DFG scratch buffers + OSR-exit side state
      → ConservativeRoots::add(...)     // per-word validation (§4.3)
      → visitor.append(roots)           // greys validated cells
      → JITStubRoutines::traceMarkedStubRoutines  // ordering-dependent side effect
```

### 4.2 Capture: stacks & registers

`ConservativeRoots` (`ConservativeRoots.h:36-63`) is a flat `HeapCell**` vector
with a 2048-entry inline array, growing into `OSAllocator::reserveAndCommit`
memory. **Only validated cell pointers are stored** — raw words that fail
filtering are dropped immediately. No dedup/sorting; duplicates are collapsed
when the visitor test-and-sets mark bits.

The conductor (the thread conducting GC on behalf of the stopped mutator)
captures its own state via `DECLARE_AND_COMPUTE_CURRENT_THREAD_STATE`
(`MachineStackMarker.h:66-74`):

```cpp
#define DECLARE_AND_COMPUTE_CURRENT_THREAD_STATE(stateName) \
    CurrentThreadState stateName; \
    stateName.stackTop = &stateName; \
    stateName.stackOrigin = Thread::currentSingleton().stack().origin(); \
    ALLOCATE_AND_GET_REGISTER_STATE(stateName ## _registerState); \
    stateName.registerState = &stateName ## _registerState
```

`gatherFromConductor` (`MachineStackMarker.cpp:44-53`) then adds the register
spill area and the `[stackTop, stackOrigin)` span. Other threads are suspended
(one static lock prevents cross-VM suspend deadlocks, rdar://20300842), their
registers read (`thread_get_state` on Darwin; a suspend-signal handler parks
`m_platformRegisters` on POSIX), and **registers + stack copied into one
contiguous private buffer** (`tryCopyOtherThreadStacks`, `:145-202`) — so the
scan touches only copy-on-write-safe private memory, never a live foreign stack.
The stack span includes the ABI red zone (`osRedZoneAdjustment`: −128 on
x86_64/Darwin-arm64). Null-SP recycled dispatch threads are skipped
(rdar://27607384); ASan-hostile raw reads are annotated `SUPPRESS_ASAN`.

**Register capture** (`RegisterState.h`) saves callee-saves per-arch (e.g.
ARM64 `x19`–`x28` inline asm), with the `setjmp`-into-zeroed-`jmp_buf`
fallback. The safety argument, verbatim (`:36-40`):

> *"ALLOCATE_AND_GET_REGISTER_STATE has to ensure that the GC sees callee-saves
> ... it's possible that the compiler chooses to use a callee-save for one of
> the caller's variables, which means that the value that we were interested in
> got spilled. In that case, we will store something bogus into the
> RegisterState, and that's OK."*

I.e. **bogus bits are harmless (worst case: a false root); missing bits are
impossible** — the compiler cannot keep a live value only in a register that
isn't spilled or saved.

### 4.3 Per-word validation — the core safety mechanism

All validation is inlined in `ConservativeRoots::genericAddPointer`
(`ConservativeRoots.cpp:70-192`). For each machine word:

1. **Preconditions**: `ASSERT(m_heap.worldIsStopped())`, `ASSERT(isMarking())`;
   `removeArrayPtrTag` strips ARM64E pointer authentication.
2. **Boxed wasm callee?** — `CalleeBits` tag test + `boxedWasmCalleeFilter`
   bloom; `markWasmCalleeIfPending` handles native callees directly.
3. **Precise allocations** — `aboveLowerBound`/`belowUpperBound` range gate,
   then `approximateBinarySearch<PreciseAllocation*>` over the sorted snapshot
   (`MarkedSpace::prepareForConservativeScan`, `MarkedSpace.cpp:326-348`), then
   `allocation->contains(pointer) && allocation->hasValidCell()`. The
   `belowUpperBound` tolerates `ptr ≤ end + 8` — a butterfly may point just
   past its object's end (`IndexingHeader`).
4. **Block membership** — mask + bloom + hash set, **with zero dereferences**:

```cpp
MarkedBlock* candidate = MarkedBlock::blockFor(pointer);        // single mask
// butterfly pointing past end of previous block? check the previous block too
if (pointer <= std::bit_cast<char*>(candidate) + sizeof(IndexingHeader)) { ... }

if (jsGCFilter.ruleOut(std::bit_cast<uintptr_t>(candidate)))     // TinyBloomFilter: only rules OUT
    return;
if (!set.contains(candidate))                                    // authoritative hash set
    return;
```

5. **Cell-boundary + liveness** — `isAtomAligned` (16-byte), then exact cell
   start via `isAtom` (range + `(atomNumber − startAtom) % atomsPerCell`),
   falling back to `cellAlign` (interior pointers) and the
   `IndexingHeader`-before-cell case, each gated by
   `handle().isLiveCell(markingVersion, newlyAllocatedVersion, isMarking, p)`:

```cpp
// MarkedBlockInlines.h:102-211 — liveness is bitmap+version based, read under
// an optimistic CountingLock fence. There is NO magic word / vtable check.
ALWAYS_INLINE bool MarkedBlock::Handle::isLive(HeapVersion markingVersion, HeapVersion newlyAllocatedVersion, bool isMarking, const HeapCell* cell)
{
    auto count = header.m_lock.tryOptimisticFencelessRead();
    if (count.value) {
        ... // version-stamped reads of m_newlyAllocated / m_marks bitmaps
        // stale marks during Full marking still record survivors
        // (staleMarksStillRecordSurvivors)
    }
    Locker locker { header.m_lock };
    ...
    return header.m_marks.get(block.atomNumber(cell));
}
```

Only after full validation does anything get dereferenced
(`markFoundGCCell` → `cell->type() == CodeBlockType` in the composite hook).

**On false positives:** a garbage word that satisfies all filters is simply
marked — the cell (and its graph) survives one extra cycle. The failure mode is
over-retention, **never a crash**, because nothing is dereferenced beyond
validated GC metadata. Bare gigacage data pointers (butterfly payload, typed
array backing) mask to unregistered block addresses and are dropped by the
bloom/set filters; pointers to the *start* of an auxiliary cell validate and
are recorded with `HeapCell::Kind::Auxiliary`.

### 4.4 JIT-side effects: stubs & CodeBlocks

The scan's `CompositeMarkHook` (`ConservativeRoots.cpp:240-264`) offers every
candidate address to `JITStubRoutineSet::mark` (binary-search the sorted
`m_range`, set `routine->m_mayBeExecuting`) and every validated CodeBlock to
`CodeBlockSet::mark` (adds to `m_currentlyExecuting`). Later in the *same*
constraint, `traceMarkedStubRoutines` visits the declared
`FixedVector<WriteBarrier<JSCell>> m_cells` of executing stubs — so stale JIT
return addresses keep stub *code* (and its embedded GC cells) alive for one
cycle but cannot resurrect a dead CodeBlock: owner liveness is checked at End
via `GCAwareJITStubRoutine::removeDeadOwners` (`!vm.heap.isMarked(m_owner)`),
and `deleteUnmarkedJettisonedStubRoutines` (`JITStubRoutineSet.cpp:133-171`)
destroys jettisoned, unreferenced, not-executing stubs
(`ASSERT(m_isJettisoned); ASSERT(!m_refCount); ASSERT(!m_mayBeExecuting);`).
Executing/compiling CodeBlocks are traced by the SeldomGreyed `"Cb"`
constraint only once black, deferring their children to a later wave. Structural
invariant (`CodeBlockSetInlines.h:42-45`): Eden conservative scanning can only
find Eden precise allocations, so **all CodeBlocks must be non-precise
allocations**.

---

## 5. Sweeping & reclamation

### 5.1 Orchestration: when sweep runs

Sweeping is **not** a `CollectorPhase`; it happens after `End` begins, in three
modes:

1. **Lazily on allocation** (the common path) — `LocalAllocator::tryAllocateIn`
   sweeps the block it is about to allocate from *to a free list*:
   `block->sweep(&m_freeList)` (`SweepToFreeList`).
2. **Incrementally on the main run loop** — `IncrementalSweeper`
   (`IncrementalSweeper.h:36-55`) is a `JSRunLoopTimer` with
   `sweepTimeSlice = 10_ms` at a 10% duty cycle, plus an opportunistic-task
   entry (`doWorkUntil(vm, deadline)` called from `VM.cpp:2077`). `sweepNextBlock`
   (`IncrementalSweeper.cpp:95-127`) walks
   `BlockDirectory::findBlockToSweep()` (`unsweptBits & ~inUseBits` under the
   `InUse` claim), sweeps `SweepOnly`, and — only on the Timer trigger —
   `shrink()`s non-empty blocks or `freeBlock()`s empty ones.
3. **Synchronously** — `Heap::sweepSynchronously` (`Heap.cpp:1243-1263`) when
   `overCriticalMemoryThreshold() || Options::sweepSynchronously() ||
   VM::isInMiniMode()`: `MarkedSpace::sweepBlocks` → `BlockDirectory::sweepAll`
   (every unswept block, `SweepOnly`), then `MarkedSpace::shrink`.

Which blocks must be swept is snapshotted at End (`BlockDirectory.cpp:367-377`):

```cpp
void BlockDirectory::snapshotUnsweptForEdenCollection() { unsweptBits() |= edenBits(); }
void BlockDirectory::snapshotUnsweptForFullCollection()  { unsweptBits()  = liveBits(); }
```

An **Eden** collection only re-sweeps blocks that held allocations since the
last GC; a **Full** collection sweeps everything. `SweepingScope`
(`SweepingScope.h:32-49`) RAII-sets `MutatorState::Sweeping` so no new GC can be
requested mid-sweep; `MarkedBlock::Handle::sweep` asserts
`heap()->assertIsMutatorOrMutatorIsStopped()` — sweeping never runs
concurrently with a mutator in this tree.

### 5.2 `Handle::sweep` → `specializedSweep`: destruction + free-list rebuild

`MarkedBlock::Handle::sweep` (`MarkedBlock.cpp:502-599`) decides the mode,
sweeps the weak set, notifies `IsoCellSet`s (`didBeginSweepingToFreeList` →
`concurrentFilter` against the block's marks/newly-allocated bits), then
dispatches destruction through the subspace's `HeapCellType`
(`finishSweep` → `finishSweepKnowingHeapCellType` → `specializedSweep<...>`).

`specializedSweep` (`MarkedBlockInlines.h:238-408`) is a 5-way template on
`{EmptyMode, SweepMode, SweepDestructionMode, ScribbleMode, NewlyAllocatedMode,
MarksMode}`. Liveness is the **union of the two versioned bitmaps** — no mark
clearing pass exists:

```cpp
WTF::BitSet<atomsPerBlock> live;
if (marksMode == MarksNotStale && newlyAllocatedMode == HasNewlyAllocated) {
    live = header.m_marks;
    live.merge(header.m_newlyAllocated);
} else if (marksMode == MarksNotStale)
    live = header.m_marks;
else
    live = header.m_newlyAllocated;          // MarkedBlockInlines.h:333-340
```

Then one `forEachSetBit` walk converts each dead run into a free interval:

```cpp
auto handleLiveCell = [&](unsigned index) {
    if (potentiallyFreeCell != index) {
        FreeCell* cell = std::bit_cast<FreeCell*>(&block.atoms()[potentiallyFreeCell]);
        pushInterval(cell, (index - potentiallyFreeCell) * atomSize);   // destroy + scribble + link
    }
    potentiallyFreeCell = index + m_atomsPerCell;
};
live.forEachSetBit([&](unsigned index) { handleLiveCell(index); });
handleLiveCell(endAtom);
...
freeList->initialize(head, secret, freedBytes);
```

`pushInterval` destroys each cell first (guarded by `jsCell->isZapped()`;
`destroyFunc(vm, jsCell)` then `jsCell->zap(HeapCell::Destruction)`), optionally
scribbles freed memory (UAF-detection aid), and links the interval with the
per-sweep secret. An all-dead block takes a fast path: one `makeLast` interval
covering the whole payload. Destruction policy comes from `CellAttributes`:
`DoesNotNeedDestruction` blocks skip the whole destructor path (their
`destructible` directory bit is clear); `MayNeedDestruction` blocks set the bit
lazily via `HeapCell::notifyNeedsDestruction()`.

### 5.3 Block outcomes

- Cleared bits: `testAndClearIsUnswept`; freelist sweeps set `eden` (the block
  may have changed liveness via allocation, so Eden GCs re-sweep it).
- **Empty block → freed**: `MarkedSpace::freeBlock` → `delete Handle` →
  `m_alignedMemoryAllocator->freeAlignedMemory(m_block)` (fastMalloc free /
  `Gigacage::free`; `OSAllocator::decommit` only in
  `StructureAlignedMemoryAllocator` for immortal-structure blocks).
  `BlockDirectory::shrink` frees all *stealable* blocks
  (`stealableBits = emptyBits & ~destructibleBits` — an empty block still
  owing destructors is not stealable).
- **End-of-marking bit flip** (`BlockDirectory::endMarking`, `:336-359`):
  `emptyBits = liveBits & ~markingNotEmptyBits;
   canAllocateBits = liveBits & ~markingRetiredBits`.
- **`lastChanceToFinalize`** (`MarkedBlock.cpp:192-207`) — VM teardown: claim
  `InUse` *or crash*, clear both bitmaps, stamp current versions, finalize all
  weak impls, then `sweep(nullptr)` — a full destructor sweep of a heap nobody
  will allocate from again.

### 5.4 Weak references & handles

Two-phase, split across mark and sweep:

1. **Reap (mark time)** — `Heap::reapWeakHandles` → `WeakBlock::reap`
   (`WeakBlock.cpp:187-209`): any `Live` impl whose cell is unmarked becomes
   `Dead` (state stored in the low bits of `m_weakHandleOwner`):
   `WeakImpl::State = Live → Dead → Finalized → Deallocated`.
2. **Finalize (sweep time)** — `WeakBlock::sweep` (`:117-129`) finalizes every
   `Dead` impl via `WeakHandleOwner::finalize(HandleSlot, context)` — this is
   where API weak callbacks (and `WeakMap` entries etc.) actually observe death.

`WeakSet::sweep` (`WeakSet.cpp:90-128`) handles finalizer reentrancy with
`WeakBlock::IterationScope`, then detaches/releases blocks: fully-empty blocks
return to a pool (`returnWeakBlockToPool`, capped at `maxPooledWeakBlocks()`
else destroyed); logically-empty-but-not-finalized blocks are detached.
`Strong`/`Handle` API handles are **roots**, never touched by sweep; only
`Weak<T>` slots are cleared. Weak reconciliation with dying referents happens
before sweep — `Heap::reconcileWeakReferencesAtGCEnd` (`Heap.cpp:671-729`):
*"Must run after marking… before sweeping, because a dying referent may still
need to be identified or read."*

### 5.5 Deferred destruction & delayed release

- **Precise allocations are swept eagerly** in the GC epilogue —
  `Heap::sweepEagerlyInEpilogue` → `MarkedSpace::sweepPreciseAllocations`
  (`MarkedSpace.cpp:256-280`): `allocation->sweep()` (weak sweep + destroy if
  dead), then empty ones either recycle into `IsoSubspace::m_lowerTierPreciseFreeList`
  or `destroy()` → `freeMemory(basePointer)`. Eden-scope is bounded by
  `m_preciseAllocationsNurseryOffsetForSweep`.
- **CodeBlocks**: `Heap::pruneDeadReferences` write-barriers still-executing
  blocks, then `CodeBlockSet::clearCurrentlyExecutingAndRemoveDeadCodeBlocks`
  (`removeIf(!isMarked)`). Stale stubs: `deleteUnmarkedCompiledCode` →
  `deleteUnmarkedJettisonedStubRoutines` (§4.4). Dead in-flight compilations:
  `removeDeadCompilerWorklistEntries`; wasm: `releaseUnmarkedWasmCallees`.
- **`Heap::releaseDelayedReleasedObjects`** (`Heap.cpp:502-534`) is
  Foundation/GLib autorelease deferral only (guarded by
  `m_delayedReleaseRecursionCount`), invoked from `lastChanceToFinalize`.
  There is **no** `m_toBeDestroyed` list or deallocation mutex in this tree.
- **ArrayBuffers** are reconciled at End, scope-aware, outside MarkedSpace:
  `Heap::sweepArrayBuffers` → `m_arrayBuffers.sweep(vm, scope)`.

### 5.6 Return to OS / Gigacage & memory pressure

- Empty MarkedBlocks are freed through their `AlignedMemoryAllocator` back end
  (fastMalloc free, `Gigacage::free`); **no `madvise`/`discardPhysicalBytes`/
  gigacage-pruning calls exist anywhere under `Source/JavaScriptCore` in this
  tree** (grep-verified). `OSAllocator::decommit` is used only by
  `StructureAlignedMemoryAllocator` (immortal-structure blocks) and
  `ConservativeRoots` growth buffers.
- Memory pressure is a *threshold*, not a callback, inside the heap:
  `Heap::overCriticalMemoryThreshold` (cached) shrinks the eden budget in
  `collectIfNecessaryOrDefer` (`m_maxEdenSizeWhenCritical`) and forces sync
  sweeping via `shouldSweepSynchronously`. Clients (e.g. `jsc.cpp:4778-4809`)
  wire `MemoryPressureHandler` to `releaseFastMallocFreeMemory(); deleteAllCode();
  collectNow(Sync, Full)`.
- The Gigacage relationship is structural: cage-confined subspaces get their
  blocks from `GigacageAlignedMemoryAllocator`; cage teardown/pruning is
  managed by the Gigacage itself, not the sweeper.

---

## 6. Safety properties, invariants & known weaknesses

**Invariants worth stating explicitly:**

1. **Allocation fast path is three instructions deep** (bounds check + bump in
   `FreeList::allocateWithCellSize`); everything else — GC poll, block search,
   block creation — is behind one `[[unlikely]]` slow-path call. The slow path
   *first* runs/assists GC (`collectIfNecessaryOrDefer`) and only then allocates,
   so blocks are rarely created into a stale heap.
2. **Free lists are secret-scrambled interval nodes**, regenerated per sweep with
   `vm.heapRandom()` — heap-spray cannot predict freelist topology, and a
   corrupted freelist decodes to garbage offsets rather than attacker-chosen
   pointers.
3. **Conservative scanning cannot crash and cannot resurrect**: mask → bloom →
   hash set → alignment arithmetic → versioned bitmaps, with zero dereferences
   before full validation; false positives cost one cycle of retention.
4. **Register capture is one-sided**: bogus bits are OK, missing bits impossible
   (callee-save argument, `RegisterState.h:36-40`).
5. **Sweeping is never concurrent with the mutator** (`assertIsMutatorOrMutatorIsStopped`),
   and the lazy sweep-to-freelist path means a block's free list exists exactly
   between its first post-GC allocation attempt and the next `stopAllocating`.
6. **Versions, not clearing**: mark/newly-allocated bitmaps are never cleared;
   heap-level version counters invalidate them lazily (`aboutToMark` →
   `resetStaleMarks` transfers survivors instead of re-marking). This is what
   makes eden collections cheap.
7. **`InUse` bit as per-block lock** with acquire/release ordering documented at
   `BlockDirectory.h:242-258` — walkers (sweeper, iterators, stealer) and the
   allocator coordinate without a per-block mutex.
8. **Differential GC verification**: `Options::verifyGC()` re-marks the whole
   heap with an independent `VerifierSlotVisitor` and asserts set inclusion —
   marking bugs become assertion failures in testing builds.

**Known weaknesses / FIXMEs (verbatim from the tree):**

- `LocalAllocator.cpp:187-200` — the block-stealing path assumes a single
  mutator (long concurrency FIXME).
- `Heap.cpp:2417-2420` — `"Cs"` must run under a safepoint: *"FIXME: Should we
  have two constraints for this? One for concurrent and one under safepoint at
  the bitter end."*
- `Heap.cpp:2404-2409` — conservative roots are not stable between GCs; the
  verifier deliberately reuses the identical snapshot.
- `ConservativeRoots.cpp:102` — wasm callee path may fall through after handling
  a native callee ("We could probably just return here").
- `ConservativeRoots.cpp:168` — string-accessed detection could be cheaper with
  a dedicated `HeapCell::Kind` or per-handle JSType.
- `HeapUtil.h:57-63` — 32-bit FIXME: a cell pointer `0xFFFFFFFF` call-frame
  entry can clash with the deleted value.
- `MarkedBlockInlines.h:538` — `isLive()` grabs a lock; not efficient inside the
  constraint solver.
- `CodeBlockSetInlines.h:42-45` — structural restriction: Eden conservative
  scanning can only find Eden precise allocations → all CodeBlocks must be
  block-allocated.
- `SpaceTimeMutatorScheduler.cpp:96-105` — *"FIXME: The feels so wrong but
  benchmarks so good"* (resetting the pause timer at `didExecuteConstraints`).
- Conservative-scan memory pressure: stale stack words are mitigated by
  `sanitizeStackForVM` (pre-zeros stale C-loop stack / LLInt spill regions),
  but over-retention by garbage words remains possible by design.

---

## 7. Core call graphs

**Allocation (small cell, e.g. `JSMap`):**
```
JSMap::create → allocateCell<JSMap> (JSCellInlines.h:170)
  → subspaceFor<JSMap>(vm) = GCClient::IsoSubspace*      (JSCell.h:318)
  → GCClient::IsoSubspace::allocate                       (IsoSubspaceInlines.h:39)
  → LocalAllocator::allocate → FreeList::allocateWithCellSize   [bump fast path]
  ⟼ exhausted → allocateSlowCase (LocalAllocator.cpp:130)
       → collectIfNecessaryOrDefer → findBlockForAllocation (lazy sweep-to-freelist)
       → tryAllocateLowerTierPrecise (IsoSubspace only)
       → BlockDirectory::tryAllocateBlock → MarkedBlock::tryCreate
       → OOM: RELEASE_ASSERT / nullptr by AllocationFailureMode
Large cell (> largeCutoff): CompleteSubspace::allocateSlow → PreciseAllocation::tryCreate
Wasm instance:                PreciseSubspace::allocate (no LocalAllocator)
```

**Marking:**
```
requestCollection (mutator takes conn) → Begin (stop world, flip versions, fence on)
  → Fixpoint: MarkingConstraintSet::executeConvergence
       roots: "Cs" (conservative scan) / "Msr" / "Sh" / "D" / "Msm"
       outgrowths: "Ws" / "O" / "Pbc" / "Jw" / "Cb"
       drain: SlotVisitor::drainInParallel → visitChildren (PossiblyBlack + fence)
  → Concurrent (world running): collector drains passively; mutator helps via
       stopIfNecessary → performIncrementOfDraining; stores hit Heap::writeBarrier
       → addToRememberedSet → m_mutatorMarkStack
  → Reloop → Fixpoint … until executeConvergence converges && visitor empty
  → End: endMarking, verifyGC, pruneDeadReferences (weak reap), prepareForAllocation
       → IncrementalSweeper::startSweeping
```

**Conservative scan (inside `"Cs"):**
```
callWithCurrentThreadState → gatherStackRoots + gatherVMRoots
  → MachineThreads::gatherConservativeRoots
       gatherFromConductor (own stack [stackTop, origin) + RegisterState)
       tryCopyOtherThreadStacks (suspend → copy regs+stack → resume → scan copy)
  → CLoopStack::gatherConservativeRoots; VM::gatherScratchBufferRoots / scanSideState
  → ConservativeRoots::add → genericAddSpan → genericAddPointer
       [ptr-auth strip | wasm callee | precise binary search |
        blockFor mask → TinyBloomFilter → MarkedBlockSet |
        isAtomAligned/isAtom/cellAlign → isLiveCell (versioned bitmaps)]
       → markFoundGCPointer (+ JITStubRoutineSet::mark / CodeBlockSet::mark side effects)
  → SlotVisitor::append(roots) → appendJSCellOrAuxiliary
  → JITStubRoutines::traceMarkedStubRoutines
```

**Sweeping:**
```
Collector::endCollectionInEachHeap
  └─ Heap::pruneDeadReferences   [reapWeakHandles, reconcileWeakGCHashTables,
        sweepArrayBuffers, snapshotUnswept (eden|full), reconcileWeakReferencesAtGCEnd,
        removeDeadCompilerWorklistEntries, deleteUnmarkedCompiledCode,
        clearCurrentlyExecutingAndRemoveDeadCodeBlocks]
  └─ Heap::prepareForAllocation → IncrementalSweeper::startSweeping
Heap::runCollectionEpilogue (mutator)
  └─ sweepEagerlyInEpilogue (precise allocations + wasm space)
  └─ if shouldSweepSynchronously → sweepSynchronously → sweepAll → shrink/freeBlock
IncrementalSweeper::doSweep → sweepNextBlock → Handle::sweep(nullptr) [→ shrink | freeBlock]
LocalAllocator::tryAllocateIn → Handle::sweep(&m_freeList)   [SweepToFreeList, lazy]
Handle::sweep → weakSet.sweep → didBeginSweepingToFreeList → finishSweep
  → finishSweepKnowingHeapCellType → specializedSweep → destroy+zap → FreeList::initialize
Heap::shutDown → lastChanceToFinalize → stopAllocatingForGood → sweep(nullptr) → freeMemory
```

---

## 8. File index

**Driver/phases:** `heap/Collector.{h,cpp}`, `heap/CollectorPhase.{h,cpp}`,
`heap/GCConductor.{h,cpp}`, `heap/MutatorScheduler*.{h,cpp}`,
`heap/{SpaceTime,StochasticSpaceTime,SynchronousStopTheWorld}MutatorScheduler.*`,
`heap/MutatorState.{h,cpp}`, `heap/GCRequest.{h,cpp}`, `heap/Synchronousness.*`

**Allocation:** `runtime/JSCellInlines.h` (entry), `runtime/JSCell.h`
(`subspaceFor`), `heap/AllocationFailureMode.h`, `heap/AllocatingScope.h`,
`heap/Subspace*`, `heap/CompleteSubspace*`, `heap/IsoSubspace*`,
`heap/PreciseSubspace*`, `heap/Allocator*`, `heap/LocalAllocator*`,
`heap/FreeList*` (+`FreeListInlines.h`), `heap/AllocatorForMode.h`,
`heap/HeapCellType*`, `heap/IsoHeapCellType*`, `heap/IsoInlinedHeapCellType*`

**Blocks/space:** `heap/MarkedBlock*` (+`MarkedBlockInlines.h`),
`heap/BlockDirectory*`, `heap/BlockDirectoryBits.h`, `heap/MarkedSpace*`
(+`MarkedSpaceInlines.h`), `heap/PreciseAllocation.{h,cpp}`,
`heap/CellContainer*`, `heap/IsoCellSet*`, `heap/MarkedBlockSet.h`

**Marking:** `heap/MarkingConstraint*`, `heap/SimpleMarkingConstraint*`,
`heap/MarkingConstraintSolver*`, `heap/MarkStack*`, `heap/GCSegmentedArray*`,
`heap/SlotVisitor*`, `heap/AbstractSlotVisitor*`, `heap/VerifierSlotVisitor*`,
`heap/VisitCounter.h`, `heap/CellState.h`, `heap/MarkStackMergingConstraint.*`,
`heap/Constraint{Concurrency,Parallelism,Volatility}.h`

**Barriers:** `runtime/WriteBarrier.h` + `WriteBarrierInlines.h`,
`heap/WriteBarrierSupport.{h,cpp}`, `Heap::writeBarrier`/`mutatorFence`/
`setMutatorShouldBeFenced` (`heap/HeapInlines.h`, `heap/Heap.cpp`)

**Conservative roots:** `heap/ConservativeRoots.{h,cpp}`,
`heap/MachineStackMarker.{h,cpp}`, `heap/RegisterState.h`,
`heap/TinyBloomFilter.h`, `heap/HeapUtil.h`,
`heap/JITStubRoutineSet.{h,cpp}`, `heap/CodeBlockSet*`,
`runtime/MachineContext.h`, `wtf/StackBounds.*`, `wtf/posix/ThreadingPOSIX.cpp`

**Sweeping:** `heap/IncrementalSweeper.{h,cpp}`, `heap/SweepingScope.h`,
`heap/DestructionMode.{h,cpp}`, `heap/Weak{Block,Set,Impl,HandleOwner}.*`,
`heap/Heap.cpp` (`pruneDeadReferences`, `sweepSynchronously`,
`sweepEagerlyInEpilogue`, `lastChanceToFinalize`, `releaseDelayedReleasedObjects`)

**Memory back ends:** `heap/AlignedMemoryAllocator.{h,cpp}`,
`heap/FastMallocAlignedMemoryAllocator.*`, `heap/GigacageAlignedMemoryAllocator.*`,
`heap/StructureAlignedMemoryAllocator.*`

**Scopes/handles:** `heap/{DeferGC,CollectingScope,PreventCollectionScope,RunningScope,ReleaseHeapAccessScope}.*`,
`heap/{Handle,Strong,Weak,StrongSet}.*`, `heap/GCDeferralContext*`

---

*Audit methodology: all citations read and spot-verified directly against
`Source/JavaScriptCore/heap/` sources in this tree; four independent deep-dive
passes (allocation, marking, conservative scanning, sweeping) cross-checked
against each other, with divergences from stock upstream WebKit flagged inline.*
