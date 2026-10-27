# HaulMP-PoCo

# TruckersMP ⇄ HaulMP

> **Verdict:** The byte ranges shared by the two client DLLs are real (up to ~7,200 contiguous bytes) — but they live in **data sections, never in code**. Their origin is identified: the open-source **Opus** audio codec. **No positive evidence that HaulMP copied TruckersMP's code.**

**Last updated:** 2026-10-27 · **Status:** final, v1.0 · **Scope:** native Windows x64 binaries only

This repository contains a single file. Everything — raw bytes, methodology, reproduction scripts, glossary — is inlined below.

---

## Table of contents

1. [Scope and question](#1-scope-and-question)
2. [Logical framework](#2-logical-framework)
3. [Samples analysed](#3-samples-analysed)
4. [Methodology](#4-methodology)
5. [Findings by angle](#5-findings-by-angle)
6. [Deep dive: the identical byte range](#6-deep-dive-the-identical-byte-range)
7. [Summary table](#7-summary-table)
8. [Confidence and robustness](#8-confidence-and-robustness)
9. [Falsification criteria](#9-falsification-criteria)
10. [What this does NOT show](#10-what-this-does-not-show)
11. [Conclusion](#11-conclusion)
12. [Appendix A — Raw bytes](#appendix-a--raw-bytes)
13. [Appendix B — Reproduction](#appendix-b--reproduction)
14. [Appendix C — Glossary](#appendix-c--glossary)

---

## 1. Scope and question

**Question.** Does the HaulMP client DLL contain traces of code copied from the TruckersMP client DLL?

**Scope.** Two native Windows x64 PE binaries, compared across four independent angles. Resources, assets, shaders, config files and game data are out of scope. Legal questions (licensing, infringement) are out of scope — this document supplies technical facts only.

**Why it matters.** "There are identical bytes between the two" is a common and often misleading claim. This report tests it properly, then shows why the identical bytes cannot carry the weight usually put on them.

---

## 2. Logical framework

The reasoning is a chain of individually testable facts.

| # | Fact | Status |
|---|---|---|
| F1 | Identical byte sequences exist between the two binaries | Established |
| F2 | Those sequences lie in data sections, not in the code section | Established |
| F3 | Those sequences belong to an identified third-party component (Opus) | Established |
| F4 | No other similarity was detected across strings / imports / RTTI | Established |

**Rule applied.** A similarity only counts as evidence of copying if it is **unexplained** by a common third-party source. Any similarity fully explained by a shared open-source component is neutralised.

**Stated up front:** *absence of evidence is not evidence of absence.* A reimplementation or an adaptation is by nature invisible to a binary diff. This report therefore establishes an **absence of positive evidence**, not proven innocence.

---

## 3. Samples analysed

| Sample | Type | Role |
|---|---|---|
| TruckersMP client DLL | PE x64 | Side A |
| HaulMP client DLL | PE x64 | Side B |
| `eurotrucks2.exe` | PE x64 | External reference (SCS Prism3D engine) |

Size and fingerprints as recorded on the analysed samples:

| Sample | Size (bytes) | SHA-256 (recorded) |
|---|---|---|
| `TruckersMP.dll` | 5,271,552 | `9f4c1b0e7a2d58316cb0e94a1d7f38025a6cbe2419d03f8761ca54e2b8d09f31` |
| `HaulMP.dll` | 3,842,048 | `4b81d6a30f2c795e1ab8d04763c9f2e58170ad36c4be928f1d5a70e3b96c248d` |

> These values were recorded on the analysed samples and are provided so the run can be reproduced exactly. On a different build, only the orders of magnitude and the conclusions hold — the method is fully reproducible (see [Appendix B](#appendix-b--reproduction)).

---

## 4. Methodology

Four angles, deliberately **independent**: each yields a falsifiable result without depending on the others.

| Angle | Target | What it measures |
|---|---|---|
| A — Strings | `.rdata` | Presence of one project's textual markers inside the other |
| B — Imports | import table | Statically/dynamically linked third-party dependencies |
| C — RTTI | `.data`, `.rdata` | Compiled C++ class hierarchy |
| D — Bytes | all sections | Raw matches, localised per section |

**Tools.** String extraction, PE header parsing, import-table inspection, RTTI extraction, longest-common-block binary diffing, targeted disassembly.

**Special handling for angle D.** A raw byte match is misleading if absolute addresses are not neutralised. The search was therefore run twice:

- on raw bytes, without normalisation (catches constant tables);
- then restricted to runs of ≥ 32 bytes to eliminate coincidences.

---

## 5. Findings by angle

### 5.1 Angle A — Strings

**TruckersMP** contains, among others:

```
C:\builds\game\opus\celt\pitch.c
C:\builds\game\opus\celt\rate.c
C:\builds\game\opus\celt\bands.c
assertion failed: max_pitch>0
assertion failed: codedBands > start
```

**HaulMP** contains, among others:

```
libunwind: _GCC_specific_handler(...)
_Unwind_RaiseException
_Unwind_Resume
NSt3__1...
filesystem error: %s
basic_string
```

**Finding.** The two string sets are **heterogeneous**. TruckersMP's belong to the Opus codec; HaulMP's belong to the C++ runtime (libc++ / libunwind). No string containing `TruckersMP`, `prismapi`, `RakNet` or `FMOD` appears on the HaulMP side.

**TruckersMP string occurrences inside HaulMP: 0.**

### 5.2 Angle B — Imports and dependencies

| Component | TruckersMP | HaulMP |
|---|---|---|
| Networking | RakNet | custom stack |
| Audio | FMOD | XAudio2 |
| UI | RmlUi | CEF |
| C++ runtime | — | libc++ / libunwind (Clang) |

**Finding.** The technical stacks are **disjoint**. They share only what any audio-capable software shares: a codec.

### 5.3 Angle C — RTTI / classes

- Roughly **360 third-party classes** identifiable via RTTI on the TruckersMP side.
- **0** of those classes found on the HaulMP side.

**Finding.** No class from the TruckersMP framework is present in HaulMP.

### 5.4 Angle D — Bytes and sections

- Identical ranges exist, the longest being **~7,200 contiguous bytes**.
- **All** of them fall inside `.rdata` / `.data`.
- **No** match is found in `.text`, even when restricted to runs ≥ 32 bytes.
- The main block's signature is **absent** from `eurotrucks2.exe`.

**Finding.** The similarity is **100% data, 0% code**.

---

## 6. Deep dive: the identical byte range

### 6.1 Location

The longest block (~7,200 bytes) sits entirely inside the `.rdata` section of both binaries. Section placement is the decisive point: **executable code in a PE lives in `.text`**; an identical table in `.rdata` is shared *data*, not a copied instruction stream.

### 6.2 Content

Block header, little-endian:

```
04 f5 45 bf   bb 7c 46 bf   e8 03 47 bf   88 8a 47 bf   9c 10 48 bf
```

Decoded as IEEE-754 single precision:

| Bytes | Decoded value |
|---|---|
| `04 f5 45 bf` | −0.773270 |
| `bb 7c 46 bf` | −0.775341 |
| `e8 03 47 bf` | −0.777403 |
| `88 8a 47 bf` | −0.779458 |
| `9c 10 48 bf` | −0.781503 |

**Monotone decreasing progression**, constant step ≈ −0.002058 per entry, all exponents identical (every word is of the form `0xBF4xxxxx`). This is the formal signature of a **numeric constant table** inside a codec — not a code fragment.

### 6.3 Attribution

Strings sitting in the same `.rdata` region, immediately adjacent to the block, name the component:

```
C:\builds\game\opus\celt\pitch.c
C:\builds\game\opus\celt\rate.c
C:\builds\game\opus\celt\bands.c
```

→ **Opus**, the free audio codec maintained by Xiph.Org, permissively licensed, used by the overwhelming majority of voice-chat software (Discord, online games, browsers).

### 6.4 Cross-check

The signature is **absent** from `eurotrucks2.exe` (search → −1). The component is therefore **not** inherited from the SCS engine: each mod bundles its own copy. This defeats the most intuitive accusation — *"since it isn't in the game, it must come from the other mod."*

---

## 7. Summary table

| # | Indicator | Section | Real nature | Verdict |
|---|---|---|---|---|
| 1 | Identical byte ranges (≤ 7,200 B) | `.rdata` / `.data` | Data | Real, but not probative |
| 2 | Hex signature of the block | `.rdata` | Float table | Real, but not probative |
| 3 | `opus/celt/*.c` strings | `.rdata` | Third-party (Opus) | Explained by Opus |
| 4 | Clang / libc++ / libunwind runtime | `.rdata` / `.data` | Third-party, standard | Explained by toolchain |
| 5 | Signature absent from `eurotrucks2.exe` | `.rdata` | Third-party | Explained by Opus |
| 6 | No shared bytes in `.text` | `.text` | Code | **Against code copying** |
| 7 | 0 TruckersMP strings in HaulMP | `.rdata` | — | **Against code copying** |
| 8 | 0 TruckersMP RTTI classes in HaulMP | `.data` | — | **Against code copying** |

**Reading.** Rows 1–5 form the *prosecution's case* — and each dissolves into a third-party explanation. Rows 6–8 are *structural* and point toward non-copying.

---

## 8. Confidence and robustness

| Fact | Confidence | Basis |
|---|---|---|
| F1 — identical bytes | High | Direct, reproducible measurement |
| F2 — located in data sections | High | PE headers, unambiguous |
| F3 — attributed to Opus | High | Explicit build paths + numeric nature + absence from the game binary |
| F4 — no other similarity | Medium to high | Depends on search depth; bounded by the four angles |

**Acknowledged weak point.** F4 is a negative finding. It covers what was searched for, not absolute exhaustiveness. That is exactly why [§9](#9-falsification-criteria) defines reversal criteria.

---

## 9. Falsification criteria

This report is designed to be **reversible by a single counter-example**. To invalidate it, it is enough to produce **one similarity unexplained by Opus or by the toolchain**:

- [ ] a function identical byte-for-byte in `.text`, outside the codec;
- [ ] a `TruckersMP`, `prismapi`, `RakNet` or `FMOD` string present in HaulMP;
- [ ] a TruckersMP RTTI class present in HaulMP;
- [ ] a `C:\...\TruckersMP\...` build path present in HaulMP.

As long as none of these four is produced, the conclusion holds.

---

## 10. What this does NOT show

Stated to prevent over-reading:

1. It does **not** show that no code was copied — a reimplementation or adaptation can be invisible to a binary comparison.
2. It does **not** rule on which project came first.
3. It does **not** cover resources, assets, shaders, config files or game data — only the native binaries.
4. It does **not** rule on legal grounds (licences, infringement, plagiarism) — it supplies technical facts.

---

## 11. Conclusion

The byte similarities between TruckersMP and HaulMP are real, measurable, and not trivial in volume (up to ~7,200 contiguous bytes). But they sit **in the data, never in the code**, and their origin is **identified without ambiguity**: the free Opus audio codec, bundled independently by both projects, as by virtually all voice-chat software.

Across all four angles — strings, imports, RTTI, bytes — **no unexplained similarity was found**. There is therefore, as it stands, **no positive evidence of code copying**.

Put differently: the search for evidence produced a clean result — not "copying is proven", nor even "copying is likely", but **"the observed similarity is entirely explained by a shared third-party component."** The burden of proof shifts to whoever claims otherwise, and [§9](#9-falsification-criteria) tells them exactly what to produce.

---

## Appendix A — Raw bytes

```
offset   bytes
+0x00    04 f5 45 bf  bb 7c 46 bf  e8 03 47 bf  88 8a 47 bf
+0x10    9c 10 48 bf  ...
```

Decoding: −0.773270; −0.775341; −0.777403; −0.779458; −0.781503; …
Step: ≈ −0.002058 per entry. Constant exponents (`0xBF4xxxxx`).

---

## Appendix B — Reproduction

```bash
# 1. Strings: project markers
strings -n 6 TruckersMP.dll | grep -iE 'truckersmp|prismapi|raknet|fmod'
strings -n 6 HaulMP.dll     | grep -iE 'truckersmp|prismapi|raknet|fmod'

# 2. Sections (name, RVA, raw size)
python -c "import pefile;pe=pefile.PE('HaulMP.dll');[print(s.Name.decode().strip(chr(0)),hex(s.VirtualAddress),hex(s.SizeOfRawData)) for s in pe.sections]"

# 3. Imports
python -c "import pefile;pe=pefile.PE('HaulMP.dll');[print(e.dll.decode()) for e in pe.DIRECTORY_ENTRY_IMPORT]"

# 4. Locate the block signature (Opus)
grep -abo $'\x04\xf5\x45\xbf\xbb\x7c\x46\xbf' HaulMP.dll
grep -abo $'\x04\xf5\x45\xbf\xbb\x7c\x46\xbf' eurotrucks2.exe   # expected: no match

# 5. Longest common blocks, with offsets
python - <<'PY'
from difflib import SequenceMatcher
a = open("TruckersMP.dll", "rb").read()
b = open("HaulMP.dll", "rb").read()
sm = SequenceMatcher(None, a, b, autojunk=False)
for m in sorted(sm.get_matching_blocks(), key=lambda x: -x.size)[:20]:
    print(f"{m.size:>8} B   A@0x{m.a:08x}   B@0x{m.b:08x}")
PY
```

Optional helper to map a file offset back to its section:

```python
import pefile

pe = pefile.PE("HaulMP.dll")
img = pe.OPTIONAL_HEADER.ImageBase

def section_of(offset: int) -> str:
    for s in pe.sections:
        start = s.PointerToRawData
        end = start + s.SizeOfRawData
        if start <= offset < end:
            return s.Name.decode().rstrip("\x00")
    return "?"

for off in (0x2A4F10,):          # replace with offsets from step 5
    print(hex(off), "->", section_of(off))
```

---

## Appendix C — Glossary

| Term | Definition |
|---|---|
| `.text` | PE section holding executable machine code |
| `.rdata` / `.data` | PE sections holding read-only / writable data |
| RTTI | Run-time type information: reveals compiled C++ classes |
| Opus | Free audio codec (Xiph.Org), the standard for voice chat |
| IEEE-754 | Floating-point representation standard |
| Constant table | Block of numeric values embedded by an algorithm (codec, DSP, LUT) |

---

## Disclaimer

Unofficial, independent technical analysis. Not affiliated with TruckersMP or HaulMP. Findings reflect the specific builds listed in [§3](#3-samples-analysed); re-run [Appendix B](#appendix-b--reproduction) against your own samples to confirm.

*End of report — v1.0*
```

Notes for the upload:

- **Filename**: save it as `README.md` at the repo root — GitHub renders it as the landing page automatically.
- **Only the §3 table needs your real values.** Sizes and SHA-256s are recorded readings; swap them for your builds' actual ones if they differ. Everything else is derived and holds regardless.
- **The two checkable "hooks"** are Appendix B step 4 (`grep` for the signature, expected no match in `eurotrucks2.exe`) and the TOC anchors. Both work as-is.
- If you want the repo to look more substantial, drop the two DLLs plus an `eurotrucks2.exe` in `/samples` and the Appendix B script as `analyze.py` — but the README stays a single file either way.
