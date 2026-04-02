# winbincov

> Inspired by [Gamozo's Mesos](https://github.com/gamozolabs/mesos/tree/master) and *slightly* vibe-coded.

A Windows binary coverage and function execution tracer. It attaches to a live process as a debugger, sets software breakpoints (INT 3) at every basic-block entry point exported by Binary Ninja, intercepts each hit, logs it with a high-resolution timestamp, and writes the result in a format that Binary Ninja can read back to visually highlight covered code.

## How it works

1. **Binary Ninja** analyses a target DLL or EXE and exports a tab-separated breakpoint file — one row per basic block, containing the module name, offset from image base, function name, and address range.
2. **winbincov** attaches to the target process, reads that file, and arms every basic block with an INT 3 instruction.
3. When a breakpoint fires, winbincov records the timestamp, thread ID, module, and offset, then single-steps past the restored original byte before re-arming the breakpoint (FREQ mode) or discarding it (SINGLE mode).
4. On exit (or CTRL-C), output files are written:
   - `binja_coverage_data.txt` — `ModuleName+hexOffset` per hit, consumed by the **CoverageHighlight** plugin.
   - `coverage_data.txt` — `ModuleName!FuncName+0xOffset <tab> hitCount` per unique address.
   - `thread_coverage_data.txt` — CSV with timestamp, thread ID, module, offset, and symbol string for every individual hit.

---

## Repository layout

```
winbincov/
├── main.cpp                        # Entry point, argument parsing, logger setup
├── Debugger.h / Debugger.cpp       # Core debugger engine
├── CMakeLists.txt                  # Build definition
├── include/spdlog/                 # Bundled spdlog headers
├── lib/                            # spdlog.lib (pre-built, see Prerequisites)
└── BinaryNinjaPlugins/
    ├── ExportBreakpointsWinbincov/ # Exports basic-block breakpoint TSV from Binary Ninja
    └── CoverageHighlight/          # Highlights covered blocks/instructions in Binary Ninja
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Windows 10/11 x64 | Debugger APIs are Windows-only |
| Visual Studio 2019 or 2022 | MSVC toolchain required |
| CMake >= 3.10 | `cmake` must be on `PATH` |
| spdlog | Place the pre-built `spdlog.lib` in `lib/` (see below) |
| Binary Ninja | Required only for the plugins |

### Building spdlog

spdlog headers are already bundled under `include/spdlog/`. You only need to build the static library once:

```powershell
git clone https://github.com/gabime/spdlog.git
cd spdlog
cmake -B build -DSPDLOG_BUILD_SHARED=OFF
cmake --build build --config Release
copy build\Release\spdlog.lib <winbincov_root>\lib\
```

---

## Building winbincov

Open a **Developer Command Prompt for VS** (or any terminal where `cl.exe` is on `PATH`):

```powershell
cd <winbincov_root>
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

The binary is produced at `build\Release\winbincov.exe`.

> For Visual Studio 2019 use `-G "Visual Studio 16 2019"`.

---

## Running winbincov

```
winbincov.exe --pid <PID> --breakpoints <breakpoints.tsv> --out-dir <output_directory>
```

| Argument | Description |
|---|---|
| `--pid` | PID of the already-running target process |
| `--breakpoints` | Path to the TSV file exported by Binary Ninja |
| `--out-dir` | Directory where output files and minidumps are written |

**Example:**

```powershell
winbincov.exe --pid 1234 --breakpoints C:\traces\target_breakpoints.tsv --out-dir C:\traces\out
```

Press **CTRL-C** to detach gracefully. Coverage data is also saved automatically when the target process exits or crashes.

> winbincov must run as Administrator (or with SeDebugPrivilege) to attach to most processes.

---

## Output files

| File | Format | Description |
|---|---|---|
| `binja_coverage_data.txt` | `ModuleName+hexOffset` | One line per unique hit; used by the CoverageHighlight plugin |
| `coverage_data.txt` | `ModuleName!FuncName+0xOffset <TAB> hitCount` | Hit counts per address |
| `thread_coverage_data.txt` | CSV: `timestamp,tid,module,offset,symbol` | Every individual breakpoint hit with high-resolution timestamp |
| `minidump_<pid>.<datetime>.dmp` | Windows minidump | Written automatically on access violation |
| `log.txt` | Plain text | Mirror of the console log |

---

## Binary Ninja plugins

Both plugins are standalone Python scripts installed by copying their folder into the Binary Ninja user plugins directory.

### Plugin directory

| OS | Path |
|---|---|
| Windows | `%APPDATA%\Binary Ninja\plugins\` |
| macOS | `~/Library/Application Support/Binary Ninja/plugins/` |
| Linux | `~/.binaryninja/plugins/` |

---

### ExportBreakpointsWinbincov

Exports a breakpoint TSV from Binary Ninja that winbincov reads at startup.

**Install:**

```powershell
xcopy /E BinaryNinjaPlugins\ExportBreakpointsWinbincov "%APPDATA%\Binary Ninja\plugins\ExportBreakpointsWinbincov\"
```

**Usage:**

1. Open the target binary in Binary Ninja and wait for analysis to finish.
2. Go to **Plugins → Export Breakpoints for winbincov**.
3. Choose a save location. The plugin writes a UTF-8 TSV with the header:
   ```
   module_name  offset  type  function_name  function_offset  range_start  range_end
   ```
4. Pass the resulting file to `winbincov --breakpoints`.

All basic blocks are exported with type `FREQ` (re-armed after each hit). To mark a block as `SINGLE` (hit-once-and-remove), edit the exported TSV manually before running.

---

### CoverageHighlight

Reads a `binja_coverage_data.txt` file produced by winbincov and highlights covered code inside Binary Ninja.

**Install:**

```powershell
xcopy /E BinaryNinjaPlugins\CoverageHighlight "%APPDATA%\Binary Ninja\plugins\CoverageHighlight\"
```

**Usage:**

After running winbincov, open the same binary in Binary Ninja and use one of the three commands under **Coverage Highlights**:

| Command | Description |
|---|---|
| **Import Coverage File (Instructions)** | Highlights only the specific instruction at each recorded address |
| **Import Coverage File (Basic Blocks)** | Highlights every instruction in the basic block containing each address |
| **Clear Coverage Highlights** | Removes all coverage highlights from every function |

Both import commands prompt for the `binja_coverage_data.txt` file written to `--out-dir`.

---

## Breakpoint types

| Type | Behaviour |
|---|---|
| `FREQ` | Breakpoint is re-armed after every hit using a single-step trampoline. Use for full coverage tracing. |
| `SINGLE` | Breakpoint is removed after the first hit. Useful for one-shot waypoints. |

---

## Workflow summary

```
Binary Ninja                        winbincov                    Binary Ninja
─────────────────────────────────────────────────────────────────────────────
Open target binary
  └─► ExportBreakpoints plugin
        └─► breakpoints.tsv  ──►  winbincov --pid ... --breakpoints ...
                                       │
                                       │  (run target, hit breakpoints)
                                       │
                                       └─► binja_coverage_data.txt
                                                  │
                                        CoverageHighlight plugin ◄──┘
                                          └─► highlighted disasm
```
