# winbincov

> Inspired by [Gamozo's Mesos](https://github.com/gamozolabs/mesos/tree/master) and *slightly* vibe-coded.

A Windows binary coverage and function execution tracer. It attaches to a live process as a debugger, sets software breakpoints at every basic-block entry point exported by Binary Ninja, intercepts each hit, logs it with a high-resolution timestamp, and writes the result in a format that Binary Ninja can read back to visually highlight covered code.

- Code coverage can be loaded into Binja using: `binja_coverage_data.txt`
- Function tracing is found in: `thread_coverage_data.txt`

## How it works

1. **Binary Ninja** analyses a target DLL or EXE and exports a tab-separated breakpoint file — one row per basic block, containing the module name, offset from image base, function name, and address range.
2. **winbincov** attaches to the target process, reads that file, and arms every basic block with software breakpoints.
3. When a breakpoint fires, winbincov records the timestamp, thread ID, module, and offset, then single-steps past the restored original byte before re-arming the breakpoint.
4. On exit (or CTRL-C), output files are written:
   - `binja_coverage_data.txt` — `ModuleName+hexOffset` per hit.
   - `coverage_data.txt` — `ModuleName!FuncName+0xOffset <tab> hitCount` per unique address.
   - `thread_coverage_data.txt` — CSV with timestamp, thread ID, module, offset, and symbol string for every individual hit.

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

> winbincov must run as Administrator and make sure to have exported the latest breakpoints using the Binja plugin!

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

## Trace Viewer

`trace_viewer.py` is a Python/Tkinter GUI for exploring `thread_coverage_data.txt` without any third-party dependencies.

```powershell
python trace_viewer.py <output_directory>
```

It opens the `thread_coverage_data.txt` file found inside `<output_directory>` (the same path passed to `--out-dir`). The viewer has three tabs:

- **Event Log** — paginated table of every recorded hit (500 events per page). Filter by thread ID or a function-name substring; right-click a row to filter to that thread or function, or copy the symbol name to the clipboard. Click any column header to sort.
- **Timeline** — dark canvas with one horizontal lane per thread. Each breakpoint hit is drawn as a colored vertical tick where the color encodes the function. Drag to pan, scroll-wheel to zoom in/out, and hover to see the exact symbol and timestamp under the cursor.
- **Function Summary** — one row per unique function showing call count, how many threads reached it, and the first/last timestamp. Click a column header to sort; double-click a row to jump straight to a filtered Event Log for that function.

Filtered events can be exported to a CSV file via **File → Export filtered events**.

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

## Building winbincov

Open a **Developer Command Prompt for VS** (or any terminal where `cl.exe` is on `PATH`):

```powershell
cd <winbincov_root>
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

The binary is produced at `build\Release\winbincov.exe`.

> For Visual Studio 2019 use `-G "Visual Studio 16 2019"`.

