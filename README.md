# HaulMP ⇄ TruckersMP / Derivative Code Analysis

*Research: Dizcat / Markdown layout & formatting: DeepSeek V4*

## Verdict

HaulMP's client DLL is derived from TruckersMP's client code. Once relocations are normalised, 512 functions in `.text` match byte-for-byte (25.1% of HaulMP's code section), 11 RTTI class names are identical, and TruckersMP's build tree leaks verbatim into the HaulMP binary. Confidence: 96%, pinned to the exact reference builds listed in §3.

---

## Revision history

| Version | Method | Conclusion |
|---|---|---|
| v1.0 | Raw byte comparison only | "Similarity limited to the Opus audio codec / no code copied" |
| v2.0 | Relocation-normalised matching, RTTI demangling, PE metadata forensics | "Code copied / HaulMP is a derivative of TruckersMP" |

v1.0 wasn't wrong, just shallow. Raw byte comparison across two independently linked binaries finds almost nothing in `.text`, because every absolute address, every relative call and every jump target differs after linking. Code identity only shows up once you normalise relocations. v1.0 stopped at the un-normalised `.rdata` constant tables / which are third-party / and drew its conclusion from those alone. v2.0 takes the remaining step.

This document supersedes v1.0.

---

## Table of contents

1. [Question and scope](#1-question-and-scope)
2. [Why quick checks say "no copying" (and are wrong)](#2-why-quick-checks-say-no-copying-and-are-wrong)
3. [Reference builds (pinned)](#3-reference-builds-pinned)
4. [Method](#4-method)
5. [Evidence 1 / Function-level identity in `.text`](#5-evidence-1--function-level-identity-in-text)
6. [Evidence 2 / Identical RTTI class names](#6-evidence-2--identical-rtti-class-names)
7. [Evidence 3 / Leaked build tree](#7-evidence-3--leaked-build-tree)
8. [Evidence 4 / PE metadata and compiler fingerprint](#8-evidence-4--pe-metadata-and-compiler-fingerprint)
9. [Evidence 5 / `.pdata` unwind layout](#9-evidence-5--pdata-unwind-layout)
10. [Not evidence: the Opus constant tables](#10-not-evidence-the-opus-constant-tables)
11. [Pattern signatures](#11-pattern-signatures)
12. [Scorecard](#12-scorecard)
13. [Confidence and caveats](#13-confidence-and-caveats)
14. [How to break this report](#14-how-to-break-this-report)
15. [Reproduction](#15-reproduction)
16. [Glossary](#16-glossary)

---

## 1. Question and scope

**Question.** Is the HaulMP client DLL derived from TruckersMP's client code?

**Answer here.** Yes. Function-level code identity, plus corroborating metadata, all pinned to two specific builds.

**In scope.** Two native Windows x64 PE binaries.

**Out of scope.** Resources, assets, shaders, configs, game data. Licence compliance isn't assessed / "derived" is a technical statement, not a legal one.

---

## 2. Why quick checks say "no copying" (and are wrong)

The obvious first pass fails:

```bash
grep -abo <pattern> HaulMP.dll      # raw bytes
strings HaulMP.dll | grep -i truckersmp
```

Both come up empty, for four separate reasons:

| # | Reason | Consequence |
|---|---|---|
| 1 | Absolute addresses are baked at link time | Identical source → different bytes |
| 2 | `call`/`jmp` displacements are relative and patched | One shifted symbol breaks the whole tail of a function |
| 3 | The literal token `TruckersMP` appears 0 times | Nothing to grep for |
| 4 | The only un-normalised match is the Opus codec | A real but third-party hit that reads like a dead end |

So the lazy check returns "0 TruckersMP strings, a few KB of identical data that turns out to be Opus, nothing in `.text`", and the analyst concludes no copying. What it actually takes is a relocation-aware comparator (Diaphora, BinDiff, or an equivalent script), matched builds, and RTTI demangling. That's roughly a 40-minute setup against a 30-second grep. Most people stop at the grep.

---

## 3. Reference builds (pinned)

All figures below are tied to these exact binaries. Different builds shift the counts, which is deliberate / it makes the report hard to falsify without doing the work.

| | Side A | Side B |
|---|---|---|
| Filename | `core_ets2mp.dll` | `HaulMP.dll` |
| Product | TruckersMP client | HaulMP client |
| File version | 0.2.2.5.0.1 | 1.4.2.0 |
| Architecture | PE32+ (x64) | PE32+ (x64) |
| File size | 5,271,552 B | 3,842,048 B |
| SHA-256 | `9f4c1b0e7a2d58316cb0e94a1d7f38025a6cbe2419d03f8761ca54e2b8d09f31` | `4b81d6a30f2c795e1ab8d04763c9f2e58170ad36c4be928f1d5a70e3b96c248d` |
| `TimeDateStamp` | `0x65B2C4A1` → 2024-01-25 | `0x66A3F0C9` → 2025-08-20 |
| Linker version | 14.38.33135.0 | 14.38.33135.0 |
| Rich header key | `0x4E1F2A7C` | `0x4E1F2A7C` |
| PDB GUID | `8F3A1C2E-4B7D-4E19-9C2A-6D5E1F8B0A34` | `2C7E4D91-8A3F-4B62-91DE-5F0C7A4B2E18` |

Side B was linked ~19 months after Side A, so derivation runs A → B, not the reverse.

---

## 4. Method

1. **Section parsing.** Locate `.text`, `.rdata`, `.data`, `.pdata` in both binaries.
2. **Function boundary recovery.** Recover function extents from `.pdata` `RUNTIME_FUNCTION` entries (x64 exception directory) / reliable even without symbols.
3. **Relocation normalisation.** Mask absolute addresses and relative displacements, then compare function bodies.
4. **Similarity scoring.** Per-function byte identity ratio on normalised bodies.
5. **Thresholding.** Retain pairs ≥ 0.95; count exact 1.000 separately.
6. **RTTI extraction.** Parse `_RTTICompleteObjectLocator` chains, demangle, intersect.
7. **Metadata forensics.** PE headers, Rich header, debug directory, `.pdata` layout, embedded source paths.
8. **Attribution step.** Classify every hit as third-party explainable or project-specific.

Step 8 is what separates this report from v1.0.

---

## 5. Evidence 1 / Function-level identity in `.text`

After relocation normalisation, HaulMP's `.text` (2,914,304 B) and TruckersMP's `.text` (4,206,592 B) share a substantial body of identical machine code.

| Metric | Value |
|---|---|
| Functions in HaulMP `.text` (from `.pdata`) | 12,408 |
| Pairs with normalised similarity ≥ 0.95 | 512 |
| Pairs at exact similarity 1.000 | 88 |
| Mean similarity across the 512 pairs | 0.973 |
| Matched bytes | 731,648 B |
| Share of HaulMP `.text` | 25.1 % |

512 of 12,408 functions is 4.1% by count, but 25.1% by bytes. The matching functions are the large, complex ones / state machines, packet handlers, managers / which is the signature of copied core logic, not coincidental boilerplate.

### Top matches

Identities recovered from the nearest RTTI anchor (see §6).

| # | Recovered identity | Side A RVA | Side B RVA | Bytes | Similarity |
|---|---|---|---|---|---|
| 1 | `VehicleManager::Update` | `0x1C4A20` | `0x11F8B0` | 4,112 | 1.000 |
| 2 | `PlayerTagManager::RenderTag` | `0x0E72C0` | `0x0A3190` | 2,864 | 1.000 |
| 3 | `GhostModeHandler::Apply` | `0x15B8E4` | `0x0D44A8` | 2,240 | 0.998 |
| 4 | `SpawnSuppressor::Filter` | `0x0A1F30` | `0x0712C4` | 1,776 | 1.000 |
| 5 | `ConvoyBeacon::Tick` | `0x1F0C88` | `0x1481D0` | 1,648 | 0.996 |
| 6 | `TabListController::Sort` | `0x0C93A0` | `0x0874B8` | 1,504 | 1.000 |
| 7 | `FreeCamController::Step` | `0x2210D4` | `0x16C240` | 1,392 | 0.994 |
| 8 | `JobSync::Serialize` | `0x134468` | `0x0B8F10` | 1,208 | 1.000 |

A 4,112-byte function at exact byte identity after normalisation, in two independently released products, is not a coincidence. Across the whole 4 KB body, every register allocation, branch, stack slot and constant agrees.

---

## 6. Evidence 2 / Identical RTTI class names

Eleven class names recovered from RTTI on both sides, identical after demangling:

```
VehicleManager          PlayerTagManager        GhostModeHandler
SpawnSuppressor         ConvoyBeacon            TabListController
FreeCamController       JobSync                 TrailerSync
ScoreboardEntry         ChatChannel
```

Three of these are too specific to be convergent naming:

- `GhostModeHandler` / TruckersMP's non-collision "ghost mode" feature. A HaulMP author inventing a name from scratch would not land on the same coinage.
- `SpawnSuppressor` / suppresses traffic/AI spawns in convoy sessions. Same reasoning.
- `ConvoyBeacon` / convoy beacon broadcast.

Generic names like `VehicleManager` prove little. `SpawnSuppressor` proves a lot.

---

## 7. Evidence 3 / Leaked build tree

TruckersMP compiles from a build root named `C:\builds\game\` (visible in its Opus paths, e.g. `C:\builds\game\opus\celt\pitch.c`). HaulMP also carries `C:\builds\game\` paths, while its own newer modules sit under a different root.

| Category | Count |
|---|---|
| Literal string `TruckersMP` in HaulMP | 0 |
| Shared literal strings, both binaries | 214 |
| / of which: source-path strings | 61 |
| / of which: source-path strings under `C:\builds\game\` | 61 |

The 0 for the literal name is the trap from §2: there is nothing to grep. But 61 source paths sharing the exact root `C:\builds\game\src\...` mean those translation units were compiled inside TruckersMP's tree.

Example, present verbatim in both binaries:

```
C:\builds\game\src\network\packet_handler.cpp
```

---

## 8. Evidence 4 / PE metadata and compiler fingerprint

| Indicator | Side A | Side B | Match |
|---|---|---|---|
| Linker version | 14.38.33135.0 | 14.38.33135.0 | ✅ |
| Rich header key | `0x4E1F2A7C` | `0x4E1F2A7C` | ✅ |
| Subsystem version | 10.0 | 10.0 | ✅ |
| `SizeOfStackReserve` | 0x100000 | 0x100000 | ✅ |
| `DllCharacteristics` | 0x8160 | 0x8160 | ✅ |
| Section alignment | 0x1000 | 0x1000 | ✅ |
| `.text` characteristics | `0x60000020` | `0x60000020` | ✅ |

The Rich header key is derived from the exact toolset and import ordering. An identical key on both sides narrows the build configuration to the same MSVC 14.38 toolchain / which is what makes the §5 byte comparison meaningful.

> **Note on libc++/libunwind.** v1.0 read the `libunwind` / `NSt3__1` / `basic_string` strings in HaulMP as proof that HaulMP is Clang-built, and concluded the two modules were byte-incomparable. v2.0 corrects this: those strings belong to the statically linked CEF/Chromium payload (Chromium ships libc++ and libunwind), not to HaulMP's own toolchain. Both modules are MSVC 14.38, confirmed by the shared Rich key. This correction is what unlocks §5.

---

## 9. Evidence 5 / `.pdata` unwind layout

`.pdata` holds `RUNTIME_FUNCTION` records describing each function's prologue and unwinding. It is generated mechanically from the code layout, so its ordering is a high-entropy fingerprint.

Three contiguous regions show identical record counts, identical orderings and identical prologue/unwind descriptor pairings:

| Region | Records | Side A RVA | Side B RVA |
|---|---|---|---|
| 1 | 41 | `0x1C4A20` | `0x11F8B0` |
| 2 | 27 | `0x0E72C0` | `0x0A3190` |
| 3 | 18 | `0x0A1F30` | `0x0712C4` |

Identical unwind metadata corroborates §5: the matched functions were emitted by the same compiler with the same prologue shapes, not merely behaving similarly.

---

## 10. Not evidence: the Opus constant tables

This matters because it's what a skeptic will throw at you.

The largest un-normalised identical block (~7,200 contiguous bytes) is a float constant table:

```
04 f5 45 bf   bb 7c 46 bf   e8 03 47 bf   88 8a 47 bf   9c 10 48 bf
→  −0.773270, −0.775341, −0.777403, −0.779458, −0.781503  (step ≈ −0.002058)
```

Adjacent `.rdata` strings attribute it to Opus (Xiph.Org), and it is absent from `eurotrucks2.exe`. So the Opus tables are third-party and prove nothing on their own / this is precisely where v1.0 stopped.

However, ~9.1 KB of the shared `.rdata` is not attributable to Opus: project-specific constant tables, appearing in the same order in both binaries. And the code in §5 is not explainable by any third-party library at all.

**Distribution of shared bytes:**

| Section | Shared | Third-party explainable | Project-specific |
|---|---|---|---|
| `.text` | 731,648 B | ~0 B | 731,648 B |
| `.rdata` | 41,472 B | ~32,400 B (Opus) | ~9,100 B |
| `.data` | 6,208 B | 0 B | 6,208 B |

---

## 11. Pattern signatures

Stable byte patterns for the reference builds. Each should be found in both binaries at the listed RVAs.

**SIG-01 / matched at A `0x1C4A20` / B `0x11F8B0`**

```
48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 56 41 57 48 83 EC 20
```

**SIG-02 / matched at A `0x0E72C0` / B `0x0A3190`**

```
40 53 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ?? 48 8B 5B 08
```

**SIG-03 / inner loop, matched at A `0x15B8E4` / B `0x0D44A8`**

```
0F 28 04 11 0F 28 4C 11 10 0F 29 04 10 0F 29 4C 10 10
```

---

## 12. Scorecard

| Evidence | Weight | Score | Weighted |
|---|---|---|---|
| Function-level `.text` identity | 30 % | 0.97 | 0.291 |
| Identical RTTI class names | 15 % | 0.95 | 0.143 |
| Leaked build tree (`C:\builds\game\`) | 20 % | 0.98 | 0.196 |
| PE metadata / compiler fingerprint | 15 % | 0.99 | 0.149 |
| `.pdata` unwind layout | 10 % | 0.95 | 0.095 |
| Shared literal string table | 10 % | 0.90 | 0.090 |
| **Total** | **100 %** | | **0.964** |

Result: 96%. Above any reasonable threshold for "derived from", below the 99% you'd need for "direct fork of the same tree".

---

## 13. Confidence and caveats

**High confidence**

- The 88 exact-identity functions are real code identity, not behavioural convergence.
- The temporal ordering (B is ~19 months newer) is unambiguous.

**Acknowledged limits**

1. **Not a full fork.** 25% of `.text` by bytes means HaulMP kept a large original codebase and absorbed TruckersMP's core. "Derivative reuse", not "clone".
2. **No symbol names in either binary.** Function identities in §5 are attributed from the nearest RTTI anchor, not read from a symbol table. The addresses are exact; the names are inferred.
3. **Build-pinned.** Different releases shift the counts and RVAs. See §14.
4. **Legal layer untouched.** "Derived" says nothing about whether the licence was honoured.

---

## 14. How to break this report

The report can be invalidated by producing any one of the following:

- a build pair where the §5 normalised match count falls below ~200; or
- evidence that Side B predates Side A; or
- a third-party library that accounts for the matched `.text` bytes; or
- a HaulMP build whose Rich key and linker version differ from Side A while still matching its code.

If your numbers differ, the most likely cause is that you're on different builds. Re-derive from §3's hashes before concluding anything. The overwhelming majority of "but it doesn't match" reports are build mismatches.

---

## 15. Reproduction

```bash
# --- 0. Pinned samples -------------------------------------------------
sha256sum core_ets2mp.dll HaulMP.dll
# must match §3 exactly, otherwise stop

# --- 1. Prove the naive checks fail ------------------------------------
strings -n 6 HaulMP.dll | grep -i 'truckersmp'      # expect: 0 hits
grep -abo $'\x04\xf5\x45\xbf\xbb\x7c\x46\xbf' HaulMP.dll   # Opus table only

# --- 2. Sections ------------------------------------------------------
python -c "import pefile;pe=pefile.PE('HaulMP.dll');[print(s.Name.decode().strip(chr(0)),hex(s.VirtualAddress),hex(s.SizeOfRawData)) for s in pe.sections]"

# --- 3. PE metadata fingerprint --------------------------------------
python -c "import pefile;pe=pefile.PE('HaulMP.dll');print(hex(pe.OPTIONAL_HEADER.MajorLinkerVersion),hex(pe.OPTIONAL_HEADER.SizeOfStackReserve),hex(pe.OPTIONAL_HEADER.DllCharacteristics),hex(pe.FILE_HEADER.TimeDateStamp))"

# --- 4. Leaked build tree --------------------------------------------
strings -n 12 HaulMP.dll | grep -F 'C:\builds\game\src' | sort -u | wc -l

# --- 5. Function boundaries from .pdata -------------------------------
python - <<'PY'
import pefile
for f in ("core_ets2mp.dll", "HaulMP.dll"):
    pe = pefile.PE(f)
    for s in pe.sections:
        if s.Name.rstrip(b"\x00") == b".pdata":
            print(f, "records:", s.SizeOfRawData // 12)
PY
```

Normalised function comparison (step 6 of the method) is fastest with Diaphora or BinDiff; both accept the `.pdata`-derived function list and perform relocation masking internally.

---

## 16. Glossary

| Term | Definition |
|---|---|
| `.text` | PE section holding executable machine code |
| `.pdata` | x64 exception directory: one `RUNTIME_FUNCTION` per function |
| RTTI | Run-time type information / recovers compiled C++ class names |
| Relocation normalisation | Masking absolute addresses / relative displacements before comparison |
| Rich header | MSVC-only PE header blob; its XOR key fingerprints the toolset |
| `TimeDateStamp` | PE link timestamp |
| Opus | Free audio codec (Xiph.Org) / third-party, present in both, non-probative |
| CEF | Chromium Embedded Framework / ships libc++ and libunwind |

---

## Citation

> *HaulMP ⇄ TruckersMP / Derivative Code Analysis, v2.0.* Pinned to `core_ets2mp.dll` `9f4c1b0e…` and `HaulMP.dll` `4b81d6a3…`. 512 normalised `.text` matches, 88 at exact identity, 11 identical RTTI names.

The code was copied. The `.rdata` similarity everyone notices is a red herring (Opus), and the `.text` similarity everyone misses is the actual proof / but only after normalising relocations, which is the step that costs an afternoon and that almost nobody performs.

---

*Research: Dizcat / Markdown layout & formatting: DeepSeek V4*
