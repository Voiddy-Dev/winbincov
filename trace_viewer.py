#!/usr/bin/env python3
"""
Thread Execution Trace Viewer
Visualize function execution traces from thread_coverage_data.txt

Usage:
    python trace_viewer.py <output_directory>

    <output_directory> is the --out-dir folder passed to winbincov.
    The viewer will open the thread_coverage_data.txt file inside it.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
import os
import sys
import math
import hashlib
import colorsys
import bisect
from collections import defaultdict

# ─── Transparent call thunks ──────────────────────────────────────────────────
#
# Windows Control Flow Guard (CFG) inserts an indirect-call stub between every
# virtual/indirect call site and its real target.  In a traced binary these
# thunks appear between every caller and its callee, polluting both the callee
# list and every reconstructed call chain.
#
# Functions whose base_func matches _THUNK_RE are treated as *transparent*:
#   • Callee view  – the thunk is skipped; whatever the thunk itself calls is
#                    reported as the real direct callee of the outer function.
#   • Caller chain – the thunk frame is walked through without being added to
#                    the displayed chain.
#
# Extend _THUNK_PATTERNS to mark additional stubs as transparent.

_THUNK_PATTERNS = re.compile(
    r'^_+guard_(dispatch|check)_icall'   # CFG dispatch/check thunks
    r'|^__guard_',                        # other __guard_* stubs
    re.IGNORECASE,
)

def _is_transparent_thunk(func_name: str) -> bool:
    return bool(_THUNK_PATTERNS.match(func_name))

# ─── Parsing ──────────────────────────────────────────────────────────────────

def parse_trace_file(path):
    """
    Parse the trace file, skipping CSV header lines.
    Returns a flat list of event dicts ordered by file appearance.
    """
    events = []

    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('timestamp,'):
                continue
            parts = line.split(',', 4)
            if len(parts) < 5:
                continue
            ts_hex, tid_hex, module, bp_offset, func_str = parts
            try:
                ts  = int(ts_hex.strip(),  16)
                tid = int(tid_hex.strip(), 16)
            except ValueError:
                continue

            m = re.match(r'^(.*?)\+0x[0-9a-fA-F]+$', func_str)
            base_func = m.group(1) if m else func_str

            events.append({
                'ts':        ts,
                'tid':       tid,
                'tid_str':   tid_hex.strip().upper(),
                'module':    module,
                'offset':    bp_offset,
                'func_str':  func_str,
                'base_func': base_func,
            })

    return events

# ─── Color helpers ────────────────────────────────────────────────────────────

THREAD_PALETTE = [
    '#4e79a7', '#f28e2b', '#e15759', '#76b7b2', '#59a14f',
    '#edc948', '#b07aa1', '#ff9da7', '#9c755f', '#bab0ac',
    '#8cd17d', '#86bcb6', '#499894', '#f1ce63', '#d37295',
]

def func_color(name):
    """Stable, saturated color for a function name."""
    h = int(hashlib.md5(name.encode()).hexdigest()[:6], 16)
    r, g, b = colorsys.hsv_to_rgb((h % 360) / 360.0, 0.70, 0.92)
    return '#{:02x}{:02x}{:02x}'.format(int(r * 255), int(g * 255), int(b * 255))

def pastel(hex_color, blend=0.25):
    """Blend a hex color toward white (for row background tints)."""
    h = hex_color.lstrip('#')
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    r = int(r + (255 - r) * (1 - blend))
    g = int(g + (255 - g) * (1 - blend))
    b = int(b + (255 - b) * (1 - blend))
    return '#{:02x}{:02x}{:02x}'.format(r, g, b)

# ─── Main Application ─────────────────────────────────────────────────────────

class TraceViewer:
    PAGE_SIZE = 500

    def __init__(self, root, filepath=None):
        self.root = root
        self.root.title("Thread Execution Trace Viewer")
        self.root.geometry("1400x900")
        self.root.minsize(900, 600)

        self.events: list = []
        self.threads: list = []
        self.thread_colors: dict = {}
        self.filtered_events: list = []

        self.current_page = 0
        self.tl_zoom   = 1.0
        self.tl_offset = 0        # horizontal pixel shift
        self._tl_drag  = None     # (start_x, start_offset)
        self._tooltip  = None

        self.filter_thread = tk.StringVar(value='All')
        self.filter_func   = tk.StringVar(value='')
        self.status_var    = tk.StringVar(value="No file loaded — use File > Open")

        self._sum_sort_col = 'total_calls'
        self._sum_sort_rev = True
        self._sum_data: list = []

        self._cs_all_funcs: list = []
        # Per-thread indices built once after load for fast call-chain reconstruction
        self._cs_thread_events: dict  = {}   # tid → [(global_idx, ev), ...]
        self._cs_thread_pos_idx: dict = {}   # tid → {global_idx: position}
        self._cs_thread_entries: dict = {}   # tid → {base_func: sorted [position, ...]}
        self._cs_callee_cache: dict   = {}   # base_func → (counts_dict, threads_dict)

        self._build_ui()

        if filepath and os.path.exists(filepath):
            self._load(filepath)

    # ══════════════════════════════════════════════════════════════════════════
    # UI Construction
    # ══════════════════════════════════════════════════════════════════════════

    def _build_ui(self):
        self._build_menu()
        self._build_toolbar()

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill='both', expand=True, padx=4, pady=(0, 4))

        self._build_log_tab()
        self._build_timeline_tab()
        self._build_summary_tab()
        self._build_callstack_tab()

        status_bar = ttk.Label(self.root, textvariable=self.status_var,
                               relief='sunken', anchor='w', padding=(6, 2))
        status_bar.pack(fill='x', side='bottom')

    def _build_menu(self):
        mb = tk.Menu(self.root)
        fm = tk.Menu(mb, tearoff=0)
        fm.add_command(label="Open…\tCtrl+O", command=self._open_file)
        fm.add_separator()
        fm.add_command(label="Export filtered events (CSV)…", command=self._export_csv)
        fm.add_separator()
        fm.add_command(label="Exit", command=self.root.quit)
        mb.add_cascade(label="File", menu=fm)

        vm = tk.Menu(mb, tearoff=0)
        vm.add_command(label="Event Log\tCtrl+1",         command=lambda: self.nb.select(0))
        vm.add_command(label="Timeline\tCtrl+2",          command=lambda: self.nb.select(1))
        vm.add_command(label="Function Summary\tCtrl+3",  command=lambda: self.nb.select(2))
        vm.add_command(label="Call Stack Analysis\tCtrl+4", command=lambda: self.nb.select(3))
        mb.add_cascade(label="View", menu=vm)

        self.root.config(menu=mb)
        self.root.bind('<Control-o>', lambda _: self._open_file())
        self.root.bind('<Control-1>', lambda _: self.nb.select(0))
        self.root.bind('<Control-2>', lambda _: self.nb.select(1))
        self.root.bind('<Control-3>', lambda _: self.nb.select(2))
        self.root.bind('<Control-4>', lambda _: self.nb.select(3))

    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=(4, 3))
        bar.pack(fill='x')

        ttk.Button(bar, text="Open File…", command=self._open_file).pack(side='left', padx=(0, 6))

        ttk.Separator(bar, orient='vertical').pack(side='left', fill='y', padx=4)

        ttk.Label(bar, text="Thread:").pack(side='left')
        self.thread_combo = ttk.Combobox(bar, textvariable=self.filter_thread,
                                          width=10, state='readonly')
        self.thread_combo.pack(side='left', padx=(2, 8))
        self.thread_combo.bind('<<ComboboxSelected>>', self._apply_filter)

        ttk.Label(bar, text="Function contains:").pack(side='left')
        func_entry = ttk.Entry(bar, textvariable=self.filter_func, width=34)
        func_entry.pack(side='left', padx=2)
        func_entry.bind('<Return>', self._apply_filter)
        ttk.Button(bar, text="Apply", command=self._apply_filter).pack(side='left', padx=2)
        ttk.Button(bar, text="Clear",  command=self._clear_filter).pack(side='left', padx=(0, 8))

        ttk.Separator(bar, orient='vertical').pack(side='left', fill='y', padx=4)
        self.count_label = ttk.Label(bar, text="", foreground='#555555')
        self.count_label.pack(side='left', padx=4)

    # ══════════════════════════════════════════════════════════════════════════
    # Tab 1 — Event Log
    # ══════════════════════════════════════════════════════════════════════════

    def _build_log_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text="  Event Log  ")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        cols = ('index', 'timestamp', 'thread', 'module', 'function', 'offset')
        self.tree = ttk.Treeview(frame, columns=cols, show='headings', selectmode='browse')

        widths = {'index': 70, 'timestamp': 130, 'thread': 68,
                  'module': 90, 'function': 580, 'offset': 90}
        for c in cols:
            self.tree.heading(c, text=c.title(),
                              command=lambda _c=c: self._log_sort(_c))
            self.tree.column(c, width=widths[c], stretch=(c == 'function'))

        vsb = ttk.Scrollbar(frame, orient='vertical',   command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient='horizontal',  command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        # Pager
        pager = ttk.Frame(frame)
        pager.grid(row=2, column=0, columnspan=2, sticky='ew', pady=3)

        ttk.Button(pager, text="◀◀ First", command=self._page_first).pack(side='left', padx=2)
        ttk.Button(pager, text="◀ Prev",   command=self._page_prev).pack(side='left', padx=2)
        self.page_label = ttk.Label(pager, text="—")
        self.page_label.pack(side='left', padx=10)
        ttk.Button(pager, text="Next ▶",   command=self._page_next).pack(side='left', padx=2)
        ttk.Button(pager, text="Last ▶▶",  command=self._page_last).pack(side='left', padx=2)

        ttk.Separator(pager, orient='vertical').pack(side='left', fill='y', padx=10)
        ttk.Label(pager, text="Jump to event #:").pack(side='left')
        self.jump_var = tk.StringVar()
        je = ttk.Entry(pager, textvariable=self.jump_var, width=10)
        je.pack(side='left', padx=2)
        je.bind('<Return>', self._jump_to_event)
        ttk.Button(pager, text="Go", command=self._jump_to_event).pack(side='left')

        # Context menu
        self._ctx_menu = tk.Menu(self.tree, tearoff=0)
        self._ctx_menu.add_command(label="Filter to this thread",          command=self._ctx_filter_thread)
        self._ctx_menu.add_command(label="Filter to this function",        command=self._ctx_filter_func)
        self._ctx_menu.add_command(label="Analyze call stack for function", command=self._ctx_analyze_stack)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="Copy function name",             command=self._ctx_copy_func)
        self._ctx_menu.add_command(label="Copy full row",                  command=self._ctx_copy_row)
        self.tree.bind('<Button-3>', self._tree_rclick)

    def _populate_log(self):
        self.tree.delete(*self.tree.get_children())
        total = len(self.filtered_events)
        pages = max(1, math.ceil(total / self.PAGE_SIZE))
        self.current_page = max(0, min(self.current_page, pages - 1))
        start = self.current_page * self.PAGE_SIZE
        end   = min(start + self.PAGE_SIZE, total)

        self.page_label.config(
            text=f"Page {self.current_page + 1} / {pages}   "
                 f"(events {start + 1:,} – {end:,} of {total:,})"
        )

        for idx in range(start, end):
            ev = self.filtered_events[idx]
            tag = f"t_{ev['tid_str']}"
            self.tree.insert('', 'end', iid=str(idx), tags=(tag,),
                values=(idx, hex(ev['ts']), ev['tid_str'],
                        ev['module'], ev['func_str'], ev['offset']))

        for tid, color in self.thread_colors.items():
            self.tree.tag_configure(f"t_{tid}", background=pastel(color, 0.12))

    def _page_first(self): self.current_page = 0;  self._populate_log()
    def _page_last(self):
        self.current_page = max(0, math.ceil(len(self.filtered_events) / self.PAGE_SIZE) - 1)
        self._populate_log()
    def _page_prev(self):
        if self.current_page > 0: self.current_page -= 1; self._populate_log()
    def _page_next(self):
        if (self.current_page + 1) * self.PAGE_SIZE < len(self.filtered_events):
            self.current_page += 1; self._populate_log()

    def _jump_to_event(self, _=None):
        try:
            n = int(self.jump_var.get())
            if 0 <= n < len(self.filtered_events):
                self.current_page = n // self.PAGE_SIZE
                self._populate_log()
                if self.tree.exists(str(n)):
                    self.tree.selection_set(str(n))
                    self.tree.see(str(n))
        except ValueError:
            pass

    def _log_sort(self, col):
        key = {'index': None, 'timestamp': 'ts', 'thread': 'tid',
               'module': 'module', 'function': 'func_str', 'offset': 'offset'}.get(col)
        if key:
            self.filtered_events.sort(key=lambda e: e[key])
            self.current_page = 0
            self._populate_log()

    def _tree_rclick(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self._ctx_menu.post(event.x_root, event.y_root)

    def _selected_event(self):
        sel = self.tree.selection()
        if sel:
            idx = int(sel[0])
            return self.filtered_events[idx] if idx < len(self.filtered_events) else None

    def _ctx_filter_thread(self):
        ev = self._selected_event()
        if not ev:
            return
        anchor_ts  = ev['ts']
        anchor_tid = ev['tid_str']
        self.filter_thread.set(anchor_tid)
        self._apply_filter()
        # Locate the same event in the freshly filtered list and scroll to it
        for new_idx, fev in enumerate(self.filtered_events):
            if fev['ts'] == anchor_ts and fev['tid_str'] == anchor_tid:
                self.current_page = new_idx // self.PAGE_SIZE
                self._populate_log()
                iid = str(new_idx)
                if self.tree.exists(iid):
                    self.tree.selection_set(iid)
                    self.tree.see(iid)
                break

    def _ctx_filter_func(self):
        ev = self._selected_event()
        if ev: self.filter_func.set(ev['base_func']); self._apply_filter()

    def _ctx_copy_func(self):
        ev = self._selected_event()
        if ev: self.root.clipboard_clear(); self.root.clipboard_append(ev['func_str'])

    def _ctx_copy_row(self):
        ev = self._selected_event()
        if ev:
            row = f"{ev['run']},{hex(ev['ts'])},{ev['tid_str']},{ev['module']},{ev['func_str']},{ev['offset']}"
            self.root.clipboard_clear(); self.root.clipboard_append(row)

    # ══════════════════════════════════════════════════════════════════════════
    # Tab 2 — Timeline
    # ══════════════════════════════════════════════════════════════════════════

    def _build_timeline_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text="  Timeline  ")
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        # Zoom controls
        ctrl = ttk.Frame(frame, padding=(4, 2))
        ctrl.grid(row=0, column=0, sticky='ew')
        ttk.Label(ctrl, text="Zoom:").pack(side='left')
        ttk.Button(ctrl, text="＋", width=3, command=self._tl_zoom_in).pack(side='left', padx=1)
        ttk.Button(ctrl, text="－", width=3, command=self._tl_zoom_out).pack(side='left', padx=1)
        ttk.Button(ctrl, text="Fit all", command=self._tl_fit).pack(side='left', padx=6)
        ttk.Label(ctrl, text="Drag to pan  |  Scroll wheel to zoom").pack(side='left', padx=10)
        self.tl_hover_label = ttk.Label(ctrl, text="", foreground='#336699')
        self.tl_hover_label.pack(side='right', padx=8)

        self.tl_canvas = tk.Canvas(frame, bg='#1a1a2a', cursor='fleur', highlightthickness=0)
        self.tl_canvas.grid(row=1, column=0, sticky='nsew')

        # Horizontal scrollbar
        tl_hsb = ttk.Scrollbar(frame, orient='horizontal', command=self._tl_hscroll_cmd)
        tl_hsb.grid(row=2, column=0, sticky='ew')
        self._tl_hsb = tl_hsb

        self.tl_canvas.bind('<Configure>',   lambda _: self._draw_timeline())
        self.tl_canvas.bind('<MouseWheel>',  self._tl_mousewheel)
        self.tl_canvas.bind('<Button-4>',    lambda _: self._tl_zoom_in())
        self.tl_canvas.bind('<Button-5>',    lambda _: self._tl_zoom_out())
        self.tl_canvas.bind('<ButtonPress-1>',   self._tl_drag_start)
        self.tl_canvas.bind('<B1-Motion>',        self._tl_drag_move)
        self.tl_canvas.bind('<ButtonRelease-1>',  lambda _: setattr(self, '_tl_drag', None))
        self.tl_canvas.bind('<Motion>',      self._tl_hover)

    # Layout constants
    TL_LABEL_W  = 190
    TL_ROW_H    = 30
    TL_HEADER_H = 38

    def _draw_timeline(self):
        c = self.tl_canvas
        c.delete('all')
        if not self.filtered_events:
            c.create_text(20, 20, text="No events loaded.", anchor='nw', fill='#666688')
            return

        W = c.winfo_width()
        H = c.winfo_height()
        if W < 10 or H < 10:
            return

        LABEL_W  = self.TL_LABEL_W
        ROW_H    = self.TL_ROW_H
        HEADER_H = self.TL_HEADER_H

        threads = sorted(set(e['tid_str'] for e in self.filtered_events))
        thread_y = {tid: HEADER_H + i * ROW_H for i, tid in enumerate(threads)}

        ts_vals = [e['ts'] for e in self.filtered_events]
        ts_min, ts_max = min(ts_vals), max(ts_vals)
        ts_range = max(1, ts_max - ts_min)

        content_px = max(W - LABEL_W, 1) * self.tl_zoom
        max_offset = max(0, content_px - (W - LABEL_W))
        self.tl_offset = min(self.tl_offset, max_offset)

        def ts_to_x(ts):
            return LABEL_W + (ts - ts_min) / ts_range * content_px - self.tl_offset

        # ── Header background
        c.create_rectangle(0, 0, W, HEADER_H, fill='#0f0f1f', outline='')

        # ── Row backgrounds + thread labels
        for i, tid in enumerate(threads):
            y    = thread_y[tid]
            bg   = '#252538' if i % 2 == 0 else '#1e1e30'
            col  = self.thread_colors.get(tid, '#888888')
            c.create_rectangle(0, y, W, y + ROW_H, fill=bg, outline='')
            c.create_rectangle(4, y + 5, 12, y + ROW_H - 5, fill=col, outline='')
            c.create_text(18, y + ROW_H // 2, text=f"TID {tid}",
                          anchor='w', fill='#ccccee', font=('Consolas', 9, 'bold'))

        # ── Time ticks
        num_ticks = max(4, min(20, int((W - LABEL_W) / 70)))
        for i in range(num_ticks + 1):
            ts = ts_min + i * ts_range / num_ticks
            x  = ts_to_x(ts)
            if LABEL_W - 1 <= x <= W + 1:
                pct = i * 100 // num_ticks
                c.create_line(x, HEADER_H - 10, x, HEADER_H, fill='#444466', width=1)
                c.create_text(x, HEADER_H - 18, text=f"{pct}%",
                              anchor='center', fill='#777799', font=('Consolas', 7))

        # ── Events — bucket by pixel for performance
        # Build per-thread pixel buckets: bucket[tid][px] = most-recent base_func
        bucket_w = max(1, int(W - LABEL_W))
        buckets: dict[str, dict[int, str]] = {tid: {} for tid in threads}

        for ev in self.filtered_events:
            tid = ev['tid_str']
            if tid not in buckets:
                continue
            px = int((ev['ts'] - ts_min) / ts_range * content_px - self.tl_offset)
            if 0 <= px < bucket_w:
                buckets[tid][px] = ev['base_func']

        # Draw one vertical line per occupied pixel
        for tid, pix_map in buckets.items():
            y = thread_y[tid]
            for px, func in pix_map.items():
                x = LABEL_W + px
                col = func_color(func)
                c.create_line(x, y + 2, x, y + ROW_H - 2, fill=col, width=1)

        # ── Bottom padding
        total_h = HEADER_H + len(threads) * ROW_H
        if total_h < H:
            c.create_rectangle(0, total_h, W, H, fill='#141420', outline='')

        # ── Update scrollbar
        if content_px > 0:
            lo = self.tl_offset / content_px
            hi = lo + (W - LABEL_W) / content_px
        else:
            lo, hi = 0.0, 1.0
        self._tl_hsb.set(lo, hi)

    def _tl_hover(self, event):
        if not self.filtered_events:
            return
        LABEL_W  = self.TL_LABEL_W
        ROW_H    = self.TL_ROW_H
        HEADER_H = self.TL_HEADER_H

        threads = sorted(set(e['tid_str'] for e in self.filtered_events))
        thread_y = {tid: HEADER_H + i * ROW_H for i, tid in enumerate(threads)}

        ts_vals = [e['ts'] for e in self.filtered_events]
        ts_min, ts_max = min(ts_vals), max(ts_vals)
        ts_range = max(1, ts_max - ts_min)
        W = self.tl_canvas.winfo_width()
        content_px = max(W - LABEL_W, 1) * self.tl_zoom

        mx, my = event.x, event.y
        hovered_tid = next((tid for tid, ty in thread_y.items()
                            if ty <= my <= ty + ROW_H), None)
        if not hovered_tid or mx <= LABEL_W:
            self.tl_hover_label.config(text="")
            return

        # Map x → timestamp
        ts_hovered = ts_min + (mx + self.tl_offset - LABEL_W) / content_px * ts_range

        # Nearest event for that thread
        best, best_dist = None, float('inf')
        for ev in self.filtered_events:
            if ev['tid_str'] == hovered_tid:
                d = abs(ev['ts'] - ts_hovered)
                if d < best_dist:
                    best_dist, best = d, ev

        if best:
            self.tl_hover_label.config(
                text=f"TID:{best['tid_str']}  {best['func_str']}  @{hex(best['ts'])}"
            )

    def _tl_zoom_in(self):
        self.tl_zoom = min(self.tl_zoom * 2.0, 2048)
        self._draw_timeline()

    def _tl_zoom_out(self):
        self.tl_zoom = max(self.tl_zoom / 2.0, 0.5)
        self._draw_timeline()

    def _tl_fit(self):
        self.tl_zoom = 1.0
        self.tl_offset = 0
        self._draw_timeline()

    def _tl_mousewheel(self, event):
        if event.delta > 0:
            self._tl_zoom_in()
        else:
            self._tl_zoom_out()

    def _tl_drag_start(self, event):
        self._tl_drag = (event.x, self.tl_offset)

    def _tl_drag_move(self, event):
        if self._tl_drag:
            dx = event.x - self._tl_drag[0]
            W = self.tl_canvas.winfo_width()
            content_px = max(W - self.TL_LABEL_W, 1) * self.tl_zoom
            max_off = max(0, content_px - (W - self.TL_LABEL_W))
            self.tl_offset = max(0.0, min(self._tl_drag[1] - dx, max_off))
            self._draw_timeline()

    def _tl_hscroll_cmd(self, *args):
        W = self.tl_canvas.winfo_width()
        content_px = max(W - self.TL_LABEL_W, 1) * self.tl_zoom
        max_off = max(0, content_px - (W - self.TL_LABEL_W))
        if args[0] == 'moveto':
            self.tl_offset = max(0, min(float(args[1]) * content_px, max_off))
        elif args[0] == 'scroll':
            step = int(args[1]) * (W // 8)
            self.tl_offset = max(0, min(self.tl_offset + step, max_off))
        self._draw_timeline()

    # ══════════════════════════════════════════════════════════════════════════
    # Tab 3 — Function Summary
    # ══════════════════════════════════════════════════════════════════════════

    def _build_summary_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text="  Function Summary  ")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        cols = ('function', 'total_calls', 'thread_count', 'threads', 'first_ts', 'last_ts')
        self.sum_tree = ttk.Treeview(frame, columns=cols, show='headings')

        cfg = {
            'function':    ('Function',      550, True),
            'total_calls': ('Calls',          70, False),
            'thread_count':('# Threads',      72, False),
            'threads':     ('Thread IDs',    200, False),
            'first_ts':    ('First Seen',    120, False),
            'last_ts':     ('Last Seen',     120, False),
        }
        for c, (label, w, stretch) in cfg.items():
            self.sum_tree.heading(c, text=label, command=lambda _c=c: self._sum_sort(_c))
            self.sum_tree.column(c, width=w, stretch=stretch)

        vsb = ttk.Scrollbar(frame, orient='vertical',   command=self.sum_tree.yview)
        hsb = ttk.Scrollbar(frame, orient='horizontal',  command=self.sum_tree.xview)
        self.sum_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.sum_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        tip = ttk.Label(frame, text="Double-click: filter Event Log  |  Right-click: analyze call stack",
                        foreground='gray', padding=(4, 2))
        tip.grid(row=2, column=0, sticky='w')

        self.sum_tree.bind('<Double-1>', self._sum_drill_down)

        self._sum_ctx_menu = tk.Menu(self.sum_tree, tearoff=0)
        self._sum_ctx_menu.add_command(label="Filter Event Log to this function", command=self._sum_drill_down)
        self._sum_ctx_menu.add_command(label="Analyze call stack",                command=self._sum_analyze_stack)
        self.sum_tree.bind('<Button-3>', self._sum_rclick)

    def _populate_summary(self):
        stats = defaultdict(lambda: {'count': 0, 'threads': set(), 'first': float('inf'), 'last': 0})
        for ev in self.filtered_events:
            s = stats[ev['base_func']]
            s['count'] += 1
            s['threads'].add(ev['tid_str'])
            s['first'] = min(s['first'], ev['ts'])
            s['last']  = max(s['last'],  ev['ts'])
        self._sum_data = [
            (func, s['count'], s['threads'], s['first'], s['last'])
            for func, s in stats.items()
        ]
        self._render_summary()

    def _render_summary(self):
        sort_keys = {
            'function':     lambda r: r[0],
            'total_calls':  lambda r: r[1],
            'thread_count': lambda r: len(r[2]),
            'threads':      lambda r: ','.join(sorted(r[2])),
            'first_ts':     lambda r: r[3],
            'last_ts':      lambda r: r[4],
        }
        key = sort_keys.get(self._sum_sort_col, sort_keys['total_calls'])
        data = sorted(self._sum_data, key=key, reverse=self._sum_sort_rev)

        self.sum_tree.delete(*self.sum_tree.get_children())
        for func, count, threads, first, last in data:
            self.sum_tree.insert('', 'end', values=(
                func, count,
                ', '.join(sorted(threads)),
                len(threads),
                hex(first), hex(last),
            ))

    def _sum_sort(self, col):
        if self._sum_sort_col == col:
            self._sum_sort_rev = not self._sum_sort_rev
        else:
            self._sum_sort_col = col
            self._sum_sort_rev = col not in ('function', 'threads')
        self._render_summary()

    def _sum_drill_down(self, _=None):
        sel = self.sum_tree.selection()
        if sel:
            func_name = self.sum_tree.item(sel[0], 'values')[0]
            self.filter_func.set(func_name)
            self._apply_filter()
            self.nb.select(0)

    # ══════════════════════════════════════════════════════════════════════════
    # Tab 4 — Call Stack Analysis
    # ══════════════════════════════════════════════════════════════════════════

    def _build_callstack_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text="  Call Stack Analysis  ")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

        # ── Left panel: function selector ─────────────────────────────────────
        left = ttk.Frame(frame, width=270)
        left.grid(row=0, column=0, sticky='nsew', padx=(4, 0), pady=4)
        left.grid_propagate(False)
        left.rowconfigure(2, weight=1)
        left.columnconfigure(0, weight=1)

        ttk.Label(left, text="Select function to analyze:").grid(
            row=0, column=0, columnspan=2, sticky='w', pady=(0, 2))

        self._cs_search_var = tk.StringVar()
        cs_entry = ttk.Entry(left, textvariable=self._cs_search_var)
        cs_entry.grid(row=1, column=0, sticky='ew', padx=(0, 2))
        ttk.Button(left, text="✕", width=2,
                   command=lambda: (self._cs_search_var.set(''), self._cs_filter_list())
                   ).grid(row=1, column=1)
        cs_entry.bind('<KeyRelease>', self._cs_filter_list)

        self._cs_listbox = tk.Listbox(
            left, selectmode='single', font=('Consolas', 8),
            activestyle='dotbox', exportselection=False,
            bg='#f5f5f5', selectbackground='#4e79a7', selectforeground='white')
        cs_vsb = ttk.Scrollbar(left, orient='vertical', command=self._cs_listbox.yview)
        self._cs_listbox.configure(yscrollcommand=cs_vsb.set)
        self._cs_listbox.grid(row=2, column=0, sticky='nsew')
        cs_vsb.grid(row=2, column=1, sticky='ns')
        self._cs_listbox.bind('<<ListboxSelect>>', self._cs_on_select)

        self._cs_func_count_label = ttk.Label(left, text="", foreground='gray')
        self._cs_func_count_label.grid(row=3, column=0, columnspan=2, sticky='w', pady=(2, 0))

        # ── Right panel: inner notebook ───────────────────────────────────────
        right = ttk.Frame(frame)
        right.grid(row=0, column=1, sticky='nsew', padx=4, pady=4)
        right.rowconfigure(0, weight=1)
        right.columnconfigure(0, weight=1)

        self._cs_inner_nb = ttk.Notebook(right)
        self._cs_inner_nb.grid(row=0, column=0, sticky='nsew')

        # Sub-tab A: Caller Patterns ───────────────────────────────────────────
        pat_frame = ttk.Frame(self._cs_inner_nb)
        self._cs_inner_nb.add(pat_frame, text="  Caller Patterns  ")
        pat_frame.rowconfigure(1, weight=1)
        pat_frame.columnconfigure(0, weight=1)

        pat_ctrl = ttk.Frame(pat_frame, padding=(4, 2))
        pat_ctrl.grid(row=0, column=0, columnspan=2, sticky='ew')
        ttk.Label(pat_ctrl,
                  text="Groups of +0x0 entry points by the call chain that preceded them (same thread).",
                  foreground='gray').pack(side='left')

        self._cs_pattern_text = tk.Text(
            pat_frame, font=('Consolas', 9), wrap='none',
            bg='#1e1e2e', fg='#cdd6f4', insertbackground='white',
            state='disabled', relief='flat')
        pat_vsb = ttk.Scrollbar(pat_frame, orient='vertical',  command=self._cs_pattern_text.yview)
        pat_hsb = ttk.Scrollbar(pat_frame, orient='horizontal', command=self._cs_pattern_text.xview)
        self._cs_pattern_text.configure(yscrollcommand=pat_vsb.set, xscrollcommand=pat_hsb.set)
        self._cs_pattern_text.grid(row=1, column=0, sticky='nsew')
        pat_vsb.grid(row=1, column=1, sticky='ns')
        pat_hsb.grid(row=2, column=0, sticky='ew')

        # Configure text tags for syntax-like highlighting
        self._cs_pattern_text.tag_configure('header',  foreground='#f1fa8c', font=('Consolas', 9, 'bold'))
        self._cs_pattern_text.tag_configure('section', foreground='#8be9fd', font=('Consolas', 9, 'bold'))
        self._cs_pattern_text.tag_configure('target',  foreground='#50fa7b', font=('Consolas', 9, 'bold'))
        self._cs_pattern_text.tag_configure('caller',  foreground='#ffb86c')
        self._cs_pattern_text.tag_configure('dim',     foreground='#6272a4')
        self._cs_pattern_text.tag_configure('count',   foreground='#bd93f9')

        # Sub-tab B: All Occurrences ───────────────────────────────────────────
        occ_frame = ttk.Frame(self._cs_inner_nb)
        self._cs_inner_nb.add(occ_frame, text="  All Occurrences  ")
        occ_frame.rowconfigure(0, weight=1)
        occ_frame.columnconfigure(0, weight=1)

        occ_cols = ('global_idx', 'timestamp', 'thread', 'module', 'function', 'entry')
        self._cs_occ_tree = ttk.Treeview(occ_frame, columns=occ_cols, show='headings', selectmode='browse')
        occ_cfg = {
            'global_idx': ('Index',     80,  False),
            'timestamp':  ('Timestamp', 120, False),
            'thread':     ('Thread',     68, False),
            'module':     ('Module',     90, False),
            'function':   ('Function',  450, True),
            'entry':      ('Entry?',     55, False),
        }
        for c, (label, w, stretch) in occ_cfg.items():
            self._cs_occ_tree.heading(c, text=label)
            self._cs_occ_tree.column(c, width=w, stretch=stretch)
        occ_vsb = ttk.Scrollbar(occ_frame, orient='vertical',  command=self._cs_occ_tree.yview)
        occ_hsb = ttk.Scrollbar(occ_frame, orient='horizontal', command=self._cs_occ_tree.xview)
        self._cs_occ_tree.configure(yscrollcommand=occ_vsb.set, xscrollcommand=occ_hsb.set)
        self._cs_occ_tree.grid(row=0, column=0, sticky='nsew')
        occ_vsb.grid(row=0, column=1, sticky='ns')
        occ_hsb.grid(row=1, column=0, sticky='ew')

        occ_tip = ttk.Label(occ_frame,
                            text="Double-click → jump to this event in Event Log",
                            foreground='gray', padding=(4, 2))
        occ_tip.grid(row=2, column=0, sticky='w')

        self._cs_occ_tree.bind('<Double-1>', self._cs_jump_to_event)
        self._cs_occ_tree.tag_configure('entry_row', background='#eaf7ea')

        # Sub-tab C: Callees ──────────────────────────────────────────────────
        callee_frame = ttk.Frame(self._cs_inner_nb)
        self._cs_inner_nb.add(callee_frame, text="  Callees  ")
        callee_frame.rowconfigure(1, weight=1)
        callee_frame.columnconfigure(0, weight=1)

        callee_ctrl = ttk.Frame(callee_frame, padding=(4, 2))
        callee_ctrl.grid(row=0, column=0, columnspan=2, sticky='ew')
        self._cs_callee_info = ttk.Label(callee_ctrl, text="", foreground='gray')
        self._cs_callee_info.pack(side='left')

        # Tree-mode treeview: function name as the tree column, counts as extras
        self._cs_callee_tree = ttk.Treeview(
            callee_frame, columns=('calls', 'threads'),
            show='tree headings', selectmode='browse')
        self._cs_callee_tree.heading('#0',      text='Function (expand ▶ for its callees)')
        self._cs_callee_tree.heading('calls',   text='Calls')
        self._cs_callee_tree.heading('threads', text='Threads')
        self._cs_callee_tree.column('#0',      width=560, stretch=True)
        self._cs_callee_tree.column('calls',   width=70,  stretch=False)
        self._cs_callee_tree.column('threads', width=70,  stretch=False)

        callee_vsb = ttk.Scrollbar(callee_frame, orient='vertical',   command=self._cs_callee_tree.yview)
        callee_hsb = ttk.Scrollbar(callee_frame, orient='horizontal',  command=self._cs_callee_tree.xview)
        self._cs_callee_tree.configure(yscrollcommand=callee_vsb.set, xscrollcommand=callee_hsb.set)
        self._cs_callee_tree.grid(row=1, column=0, sticky='nsew')
        callee_vsb.grid(row=1, column=1, sticky='ns')
        callee_hsb.grid(row=2, column=0, sticky='ew')

        callee_tip = ttk.Label(
            callee_frame,
            text="▶ expand to drill into that function's own callees  |  double-click → full analysis",
            foreground='gray', padding=(4, 2))
        callee_tip.grid(row=3, column=0, sticky='w')

        self._cs_callee_tree.bind('<<TreeviewOpen>>', self._cs_callee_expand)
        self._cs_callee_tree.bind('<Double-1>',       self._cs_callee_dblclick)

    # ── Call Stack helpers ────────────────────────────────────────────────────

    def _cs_populate_list(self):
        self._cs_all_funcs = sorted(set(e['base_func'] for e in self.events))
        self._cs_build_indices()
        self._cs_filter_list()

    def _cs_build_indices(self):
        """
        Build three per-thread lookup structures used by _cs_analyze.
        Called once after every file load — O(N) in total events.

          _cs_thread_events[tid]      = [(global_idx, ev), ...]  (file order)
          _cs_thread_pos_idx[tid]     = {global_idx: position_in_above_list}
          _cs_thread_entries[tid]     = {base_func: sorted list of positions
                                         where that function has a +0x0 event}
        """
        te:  dict = defaultdict(list)
        for i, ev in enumerate(self.events):
            te[ev['tid_str']].append((i, ev))

        tpi: dict = {
            tid: {gi: p for p, (gi, _) in enumerate(evs)}
            for tid, evs in te.items()
        }

        tent: dict = {}
        for tid, evs in te.items():
            func_entries: dict = defaultdict(list)
            for p, (_, ev) in enumerate(evs):
                if re.search(r'\+0x0$', ev['func_str']):
                    func_entries[ev['base_func']].append(p)
            tent[tid] = dict(func_entries)   # already sorted (appended in order)

        self._cs_thread_events  = dict(te)
        self._cs_thread_pos_idx = tpi
        self._cs_thread_entries = tent
        self._cs_callee_cache   = {}   # invalidate on every reload

    def _cs_filter_list(self, _=None):
        q = self._cs_search_var.get().lower()
        matches = [f for f in self._cs_all_funcs if q in f.lower()]
        self._cs_listbox.delete(0, 'end')
        for f in matches:
            self._cs_listbox.insert('end', f)
        self._cs_func_count_label.config(
            text=f"{len(matches):,} of {len(self._cs_all_funcs):,} functions"
        )

    def _cs_on_select(self, _=None):
        sel = self._cs_listbox.curselection()
        if sel:
            self._cs_analyze(self._cs_listbox.get(sel[0]))

    def _cs_select_function(self, func_name):
        """Switch to the Call Stack tab, select func_name in the list, and run analysis."""
        self.nb.select(3)
        # Clear search, repopulate, then find the entry
        self._cs_search_var.set('')
        self._cs_filter_list()
        items = list(self._cs_listbox.get(0, 'end'))
        if func_name in items:
            idx = items.index(func_name)
            self._cs_listbox.selection_clear(0, 'end')
            self._cs_listbox.selection_set(idx)
            self._cs_listbox.see(idx)
        self._cs_analyze(func_name)

    def _cs_analyze(self, func_name):
        """
        Build caller-pattern and occurrence data for func_name.

        Stack reconstruction — walk-up algorithm
        ─────────────────────────────────────────
        Old approach (wrong): collected the last N +0x0 events on the thread.
        Those could be from completely different call chains that had already
        returned, producing garbage results.

        Correct approach used here:
          1. The event immediately before Target+0x0 belongs to the direct caller
             (it was the last thing running on that thread before the call).
          2. Find that caller's own +0x0 (its entry) via binary search in the
             precomputed sorted entry-position list — O(log N).
          3. The event immediately before THAT entry belongs to the caller's
             caller.  Repeat up to MAX_CHAIN_DEPTH levels.

        Because each step moves strictly backward in time (entry_pos is always
        less than the previous scan position) there are no cycles.
        ENTRY_SEARCH_WINDOW caps how far back we look for a caller's +0x0 so
        that stale entries from previous, unrelated call chains are ignored.
        """
        MAX_CHAIN_DEPTH     = 12     # real (non-thunk) frames to record
        MAX_ITER            = 24     # total loop iterations (double to allow thunk steps)
        ENTRY_SEARCH_WINDOW = 6000   # positions back when hunting for a caller's +0x0

        te   = self._cs_thread_events
        tpi  = self._cs_thread_pos_idx
        tent = self._cs_thread_entries

        occurrences = [(i, ev) for i, ev in enumerate(self.events)
                       if ev['base_func'] == func_name]
        entry_occurrences = [(i, ev) for i, ev in occurrences
                             if re.search(r'\+0x0$', ev['func_str'])]

        entry_chains: dict = defaultdict(list)

        for g_idx, ev in entry_occurrences:
            tid = ev['tid_str']
            t_evs   = te.get(tid, [])
            pos_idx = tpi.get(tid, {})
            entries = tent.get(tid, {})

            start_pos = pos_idx.get(g_idx)
            if start_pos is None:
                continue

            chain = []
            # scan = thread-local position of the event we're examining next
            scan = start_pos - 1

            # Skip any trailing events that belong to func_name itself
            # (can happen when func_name just returned and is immediately re-entered)
            while scan >= 0 and t_evs[scan][1]['base_func'] == func_name:
                scan -= 1

            depth = 0   # counts only real (non-thunk) frames added to chain
            for _ in range(MAX_ITER):
                if scan < 0 or depth >= MAX_CHAIN_DEPTH:
                    break

                # ── Step 1: identify the frame at this scan position ──────────
                _, ev_at = t_evs[scan]
                caller_func = ev_at['base_func']

                # Transparent thunks (CFG stubs etc.) are walked through without
                # being recorded — they don't count toward MAX_CHAIN_DEPTH either.
                if not _is_transparent_thunk(caller_func):
                    chain.append(caller_func)
                    depth += 1

                # ── Step 2: find this frame's own +0x0 via binary search ──────
                positions = entries.get(caller_func, [])
                idx = bisect.bisect_right(positions, scan) - 1
                if idx < 0:
                    break   # function was never entered before this point

                entry_pos = positions[idx]

                # Reject entries that are too far back — they belong to an
                # unrelated call chain that completed long ago
                if scan - entry_pos > ENTRY_SEARCH_WINDOW:
                    break

                # ── Step 3: move up — look just before the frame's entry ──────
                scan = entry_pos - 1

            chain.reverse()   # oldest caller first, direct caller last
            entry_chains[tuple(chain)].append(g_idx)

        self._cs_render_patterns(func_name, entry_chains, entry_occurrences)
        self._cs_render_occurrences(func_name, occurrences)
        self._cs_render_callees(func_name)

    def _cs_render_patterns(self, func_name, patterns, entry_occurrences):
        txt = self._cs_pattern_text
        txt.config(state='normal')
        txt.delete('1.0', 'end')

        total_entries = len(entry_occurrences)
        all_occ_count = sum(
            1 for ev in self.events if ev['base_func'] == func_name
        )

        txt.insert('end', f"Function: ", 'dim')
        txt.insert('end', f"{func_name}\n", 'header')
        txt.insert('end',
                   f"Total hits: {all_occ_count:,}  |  "
                   f"Entry points (+0x0): {total_entries:,}  |  "
                   f"Distinct call patterns: {len(patterns):,}\n", 'dim')
        txt.insert('end', "─" * 100 + "\n\n", 'dim')

        if not patterns:
            txt.insert('end', "  No entry points (+0x0) found for this function.\n", 'dim')
            txt.insert('end', "  (Function may only appear as interior basic-block hits, not as first-calls.)\n", 'dim')
            txt.config(state='disabled')
            return

        sorted_patterns = sorted(patterns.items(), key=lambda x: len(x[1]), reverse=True)

        for rank, (chain, indices) in enumerate(sorted_patterns, 1):
            pct = len(indices) * 100 / total_entries if total_entries else 0
            txt.insert('end', f"  Pattern #{rank}  ", 'section')
            txt.insert('end', f"({len(indices):,} call{'s' if len(indices) != 1 else ''}  —  {pct:.1f}%)\n", 'count')

            if chain:
                txt.insert('end', "  Call chain (oldest → newest entry point before target):\n", 'dim')
                for depth, caller in enumerate(chain):
                    indent = "    " + "  " * depth
                    connector = "└─► " if depth == len(chain) - 1 else "├─ "
                    txt.insert('end', f"{indent}{connector}", 'dim')
                    txt.insert('end', f"{caller}\n", 'caller')
                # Arrow into target
                indent = "    " + "  " * len(chain)
                txt.insert('end', f"{indent}└─► ", 'dim')
                txt.insert('end', f"{func_name}  ← (entry)\n", 'target')
            else:
                txt.insert('end', "  No preceding entry events found within lookback window.\n", 'dim')
                txt.insert('end', f"  └─► ", 'dim')
                txt.insert('end', f"{func_name}  ← (entry)\n", 'target')

            # Show sample event indices
            sample = sorted(indices)[:15]
            sample_str = ', '.join(str(x) for x in sample)
            if len(indices) > 15:
                sample_str += f"  (+{len(indices) - 15} more)"
            txt.insert('end', f"  Event indices: {sample_str}\n\n", 'dim')

        txt.config(state='disabled')

    def _cs_render_occurrences(self, func_name, occurrences):
        self._cs_occ_tree.delete(*self._cs_occ_tree.get_children())
        for g_idx, ev in occurrences:
            is_entry = re.search(r'\+0x0$', ev['func_str']) is not None
            tags = ('entry_row',) if is_entry else ()
            self._cs_occ_tree.insert('', 'end', tags=tags, values=(
                g_idx,
                hex(ev['ts']),
                ev['tid_str'],
                ev['module'],
                ev['func_str'],
                'YES' if is_entry else '',
            ))

    # ── Callees tab ───────────────────────────────────────────────────────────

    def _resolve_caller(self, pos: int, t_evs: list,
                        entries_for_tid: dict) -> str | None:
        """
        Return the effective caller of the function entered at thread-local
        position `pos`, resolving any transparent thunk chain.

        If the event at pos-1 is a thunk, we find that thunk's own +0x0 entry
        and look at what called *it*, repeating up to MAX_THUNK_DEPTH times.
        This makes CFG dispatch stubs invisible to the call graph.
        """
        MAX_THUNK_DEPTH = 4
        scan = pos
        for _ in range(MAX_THUNK_DEPTH + 1):
            if scan <= 0:
                return None
            prev_func = t_evs[scan - 1][1]['base_func']
            if not _is_transparent_thunk(prev_func):
                return prev_func
            # Walk through the thunk: find its +0x0 entry, then look above that
            thunk_positions = entries_for_tid.get(prev_func, [])
            idx = bisect.bisect_right(thunk_positions, scan - 1) - 1
            if idx < 0:
                return prev_func   # thunk entry not found; return as-is
            scan = thunk_positions[idx]   # now scan points at the thunk's entry
        return None

    def _find_direct_callees(self, target_func):
        """
        Return (counts, threads) where:
          counts[callee]  = number of times target_func directly called callee
          threads[callee] = set of tids on which that call was observed

        A function F is a *direct* callee of target_func when a F+0x0 event
        appears on a thread and _resolve_caller(pos) == target_func.
        _resolve_caller walks through any transparent thunk chain so that CFG
        dispatch stubs are invisible — the thunk is neither shown as a callee
        nor obscures the real target of an indirect call.

        Results are cached in self._cs_callee_cache so repeated expansions of
        the same node are instant.
        """
        if target_func in self._cs_callee_cache:
            return self._cs_callee_cache[target_func]

        counts:  dict = defaultdict(int)
        threads: dict = defaultdict(set)

        for tid, t_evs in self._cs_thread_events.items():
            entries_for_tid = self._cs_thread_entries.get(tid, {})
            for func, positions in entries_for_tid.items():
                if func == target_func:
                    continue
                if _is_transparent_thunk(func):
                    continue   # never report a thunk as a callee
                for pos in positions:
                    if pos > 0:
                        effective = self._resolve_caller(pos, t_evs, entries_for_tid)
                        if effective == target_func:
                            counts[func]  += 1
                            threads[func].add(tid)

        result = (dict(counts), {f: set(ts) for f, ts in threads.items()})
        self._cs_callee_cache[target_func] = result
        return result

    def _cs_render_callees(self, func_name):
        """Populate the Callees treeview with the direct callees of func_name."""
        self._cs_callee_tree.delete(*self._cs_callee_tree.get_children())

        counts, threads = self._find_direct_callees(func_name)
        if not counts:
            self._cs_callee_info.config(
                text=f"No direct callees found for: {func_name}")
            return

        total_calls = sum(counts.values())
        self._cs_callee_info.config(
            text=f"Direct callees: {len(counts):,} distinct  |  {total_calls:,} total calls  "
                 f"(expand ▶ to drill down)")

        for callee, call_count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            iid = self._cs_callee_tree.insert(
                '', 'end',
                text=callee,
                values=(call_count, len(threads[callee])))
            # Add sentinel child so the expand arrow is shown; replaced lazily on open
            self._cs_callee_tree.insert(iid, 'end', text='', values=('', ''),
                                        tags=('_lazy_',))

    def _cs_callee_expand(self, _=None):
        """
        Lazily populate children when a callee row is expanded.
        Replaces the sentinel child with actual direct callees of that function.
        """
        iid = self._cs_callee_tree.focus()
        if not iid:
            return

        children = self._cs_callee_tree.get_children(iid)
        # Only act when we still have the unloaded sentinel
        if not (len(children) == 1 and
                '_lazy_' in self._cs_callee_tree.item(children[0], 'tags')):
            return

        func_name = self._cs_callee_tree.item(iid, 'text')
        self._cs_callee_tree.delete(children[0])   # remove sentinel

        counts, threads = self._find_direct_callees(func_name)
        if not counts:
            self._cs_callee_tree.insert(iid, 'end',
                                        text='(no direct callees found)',
                                        values=('', ''), tags=('_empty_',))
            return

        for callee, call_count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            child_iid = self._cs_callee_tree.insert(
                iid, 'end',
                text=callee,
                values=(call_count, len(threads[callee])))
            # Every child also gets a sentinel so it too can be expanded
            self._cs_callee_tree.insert(child_iid, 'end', text='', values=('', ''),
                                        tags=('_lazy_',))

    def _cs_callee_dblclick(self, _=None):
        """Double-click a callee row → run full analysis for that function."""
        iid = self._cs_callee_tree.focus()
        if not iid:
            return
        func_name = self._cs_callee_tree.item(iid, 'text')
        tags = self._cs_callee_tree.item(iid, 'tags')
        if func_name and '_empty_' not in tags and '_lazy_' not in tags:
            self._cs_select_function(func_name)

    def _cs_jump_to_event(self, _=None):
        """Double-click in occurrences table → navigate to the event in Event Log."""
        sel = self._cs_occ_tree.selection()
        if not sel:
            return
        g_idx = int(self._cs_occ_tree.item(sel[0], 'values')[0])
        # Reset filters so the event is visible, then jump
        self.filter_thread.set('All')
        self.filter_func.set('')
        self.filtered_events = self.events[:]
        self.current_page = 0
        self._refresh_all()
        self.nb.select(0)
        self.jump_var.set(str(g_idx))
        self._jump_to_event()

    # ── Context menu helpers (Event Log + Summary) ────────────────────────────

    def _ctx_analyze_stack(self):
        ev = self._selected_event()
        if ev:
            self._cs_select_function(ev['base_func'])

    def _sum_rclick(self, event):
        item = self.sum_tree.identify_row(event.y)
        if item:
            self.sum_tree.selection_set(item)
            self._sum_ctx_menu.post(event.x_root, event.y_root)

    def _sum_analyze_stack(self):
        sel = self.sum_tree.selection()
        if sel:
            func_name = self.sum_tree.item(sel[0], 'values')[0]
            self._cs_select_function(func_name)

    # ══════════════════════════════════════════════════════════════════════════
    # Load / Filter / Export
    # ══════════════════════════════════════════════════════════════════════════

    def _open_file(self):
        path = filedialog.askopenfilename(
            title="Open trace file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialdir=os.getcwd(),
        )
        if path:
            self._load(path)

    def _load(self, path):
        self.status_var.set(f"Loading {os.path.basename(path)} …")
        self.root.update_idletasks()
        try:
            events = parse_trace_file(path)
        except Exception as e:
            messagebox.showerror("Load error", str(e))
            self.status_var.set("Load failed.")
            return

        self.events = events

        threads = sorted(set(e['tid_str'] for e in events))
        self.threads = threads
        self.thread_colors = {
            tid: THREAD_PALETTE[i % len(THREAD_PALETTE)]
            for i, tid in enumerate(threads)
        }

        self.thread_combo['values'] = ['All'] + threads
        self.filter_thread.set('All')
        self.filter_func.set('')

        self.filtered_events = events[:]
        self.current_page    = 0
        self.tl_offset       = 0
        self.tl_zoom         = 1.0

        self._refresh_all()
        self.status_var.set(
            f"{os.path.basename(path)}  —  "
            f"{len(events):,} events  |  "
            f"{len(threads)} thread(s)"
        )

    def _apply_filter(self, _=None):
        tid_f  = self.filter_thread.get()
        func_f = self.filter_func.get().lower()

        self.filtered_events = [
            e for e in self.events
            if (tid_f  == 'All' or e['tid_str'] == tid_f)
            and (func_f == ''   or func_f in e['func_str'].lower())
        ]
        self.current_page = 0
        self._refresh_all()

    def _clear_filter(self):
        self.filter_thread.set('All')
        self.filter_func.set('')
        self._apply_filter()

    def _refresh_all(self):
        n = len(self.filtered_events)
        total = len(self.events)
        self.count_label.config(
            text=f"{n:,} of {total:,} events shown"
            if n != total else f"{n:,} events"
        )
        self._populate_log()
        self._populate_summary()
        self._draw_timeline()
        self._cs_populate_list()

    def _export_csv(self):
        if not self.filtered_events:
            messagebox.showinfo("Export", "No events to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export filtered events",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write("timestamp,thread_id,module,function,offset\n")
                for ev in self.filtered_events:
                    f.write(f"{hex(ev['ts'])},{ev['tid_str']},"
                            f"{ev['module']},{ev['func_str']},{ev['offset']}\n")
            messagebox.showinfo("Export", f"Exported {len(self.filtered_events):,} events to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export error", str(e))


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python trace_viewer.py <output_directory>")
        print("  <output_directory> is the --out-dir folder passed to winbincov.")
        sys.exit(1)

    out_dir = sys.argv[1]
    trace_file = os.path.join(out_dir, "thread_coverage_data.txt")

    if not os.path.isdir(out_dir):
        print(f"Error: '{out_dir}' is not a directory.")
        sys.exit(1)
    if not os.path.exists(trace_file):
        print(f"Error: '{trace_file}' not found.")
        sys.exit(1)

    root = tk.Tk()
    try:
        root.tk.call('tk', 'scaling', 1.25)
    except Exception:
        pass

    TraceViewer(root, trace_file)
    root.mainloop()


if __name__ == '__main__':
    main()
