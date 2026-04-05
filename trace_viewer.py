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
from collections import defaultdict

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
        vm.add_command(label="Event Log\tCtrl+1",    command=lambda: self.nb.select(0))
        vm.add_command(label="Timeline\tCtrl+2",     command=lambda: self.nb.select(1))
        vm.add_command(label="Function Summary\tCtrl+3", command=lambda: self.nb.select(2))
        mb.add_cascade(label="View", menu=vm)

        self.root.config(menu=mb)
        self.root.bind('<Control-o>', lambda _: self._open_file())
        self.root.bind('<Control-1>', lambda _: self.nb.select(0))
        self.root.bind('<Control-2>', lambda _: self.nb.select(1))
        self.root.bind('<Control-3>', lambda _: self.nb.select(2))

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
        self._ctx_menu.add_command(label="Filter to this thread",   command=self._ctx_filter_thread)
        self._ctx_menu.add_command(label="Filter to this function", command=self._ctx_filter_func)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="Copy function name",      command=self._ctx_copy_func)
        self._ctx_menu.add_command(label="Copy full row",           command=self._ctx_copy_row)
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
        if ev: self.filter_thread.set(ev['tid_str']); self._apply_filter()

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

        tip = ttk.Label(frame, text="Double-click a row to filter the Event Log to that function.",
                        foreground='gray', padding=(4, 2))
        tip.grid(row=2, column=0, sticky='w')

        self.sum_tree.bind('<Double-1>', self._sum_drill_down)

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
    # Load / Filter / Export
    # ══════════════════════════════════════════════════════════════════════════

    def _open_file(self):
        initial = os.path.dirname(DEFAULT_FILE) if os.path.exists(DEFAULT_FILE) else os.getcwd()
        path = filedialog.askopenfilename(
            title="Open trace file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialdir=initial,
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
