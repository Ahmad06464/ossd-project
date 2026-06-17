import customtkinter as ctk
import json
import subprocess
import threading
import time
import traceback
import webbrowser
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from tkinter import Menu, TclError, filedialog, messagebox, simpledialog, ttk

from config_loader import load_config, save_config
from export_results import export_excel, export_txt
from gui_helpers import (
    ToolTip,
    WrapDataTable,
    configure_tree_style,
    configure_scrollbar_style,
    CTK_SCROLLBAR_KWARGS,
    ensure_app_icon,
    row_tags_for_tree,
    status_row_tag,
    FONT_XS,
    FONT_SM,
    FONT_MD,
    FONT_LG,
    FONT_XL,
    FONT_APP_TITLE,
    FONT_BRAND,
    FONT_SECTION,
    FONT_DIALOG_TITLE,
    FONT_STATS_LABEL,
    FONT_STATS_NUM,
    TOOL_GROUPS,
    TOOL_STATUS_STYLE,
    shorten_tool_name,
)
from html_report import export_html
from recon_patterns import is_js_url
from scan_runner import SCAN_PROFILES, TOOL_NAMES, ScanRunner
from scan_import_export import build_scan_payload, format_scan_time, import_scan_file
from scan_resume import can_resume, capture_resume_state, extract_resume_fields, build_runner_state_from_ui
from scan_storage import (
    create_scan_session,
    default_workspace,
    ensure_workspace,
    is_workspace_writable,
    latest_session,
    load_session_from_disk,
    read_session_meta,
    resolve_workspace,
    save_session_findings,
    save_session_meta,
)
from session_manager import diff_sessions, load_session, save_session
from url_utils import normalize_url
from wordlist_manager import (
    COMMON_WORDLIST,
    MY_WORDLIST,
    append_endpoints,
    endpoint_in_wordlist,
    ensure_wordlist_files,
    normalize_endpoint,
    push_my_wordlist_to_github,
)


def init_theme():
    cfg = load_config()
    mode = cfg.get("appearance_mode", "dark")
    if mode not in ("dark", "light", "system"):
        mode = "dark"
    ctk.set_appearance_mode(mode)


init_theme()
ctk.set_default_color_theme("dark-blue")


class ReconDashboard(ctk.CTk):

    VIEWS = ("Subdomains", "URLs", "IPs", "Buckets", "Sensitive", "JS")
    MANUAL_TOOL = "Manual"

    def __init__(self):
        super().__init__()
        self.title("Recon Intelligence Dashboard")
        self.geometry("1600x950")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        cfg = load_config()
        self.profile_var = ctk.StringVar(value=cfg.get("default_scan_profile", "Full"))
        self.selected_tools = set(SCAN_PROFILES.get(self.profile_var.get(), TOOL_NAMES))
        self.scan_workspace = resolve_workspace(cfg.get("scan_workspace"))
        if cfg.get("scan_workspace") != self.scan_workspace:
            cfg["scan_workspace"] = self.scan_workspace
            save_config(cfg)

        self.results = []
        self.hosts = {}
        self.urls = {}
        self.ips = {}
        self.buckets = {}
        self.sensitive = {}
        self.js_files = {}
        self.import_hosts = []
        self.scanning = False
        self.stop_requested = False
        self.runner = None
        self.scan_start_time = 0.0
        self.current_target = ""
        self.last_scan_time = ""
        self.loaded_scan_label = ""
        self.current_session_dir = None
        self.tool_vars = {}
        self.completed_tools = []
        self.resume_state = None
        self._resume_mode = False
        self._current_view = "Subdomains"
        self.sort_state = {view: {"col": None, "reverse": False} for view in self.VIEWS}
        self.logs_visible = True
        self.sidebar_visible = True
        self._stats_labels = {}
        self._stats_text_cache = {}
        self._view_refresh_job = None
        self._search_result_cache = ""

        self.ui_font = ctk.CTkFont(family="Arial", size=15)
        self.ui_font_sm = ctk.CTkFont(family="Arial", size=13)
        self.ui_font_lg = ctk.CTkFont(family="Arial", size=17)

        self._build_topbar()
        self._build_sidebar()
        self._build_main()
        self._build_tables()
        self._bind_shortcuts()
        ensure_wordlist_files()
        self._setup_drag_drop()
        ensure_app_icon(self)
        self._update_stats_display()
        self.update_window_title()
        self.switch_view("Subdomains")
        self.after(300, self._init_scan_workspace)

    def _build_topbar(self):
        self.topbar = ctk.CTkFrame(self, height=52, corner_radius=0)
        self.topbar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 0))

        ctk.CTkLabel(
            self.topbar, text="Recon Intelligence Dashboard", font=FONT_APP_TITLE,
        ).pack(side="left", padx=12)

        actions = ctk.CTkFrame(self.topbar, fg_color="transparent")
        actions.pack(side="right", padx=8)

        self.wordlist_btn = ctk.CTkButton(
            actions, text="📝 Wordlist", width=104, height=36, font=self.ui_font,
            command=self.toggle_wordlist_panel,
        )
        self.wordlist_btn.pack(side="left", padx=4)
        self._wordlist_panel = None
        self._wordlist_status_var = ctk.StringVar(value="")

        self.sidebar_topbar_btn = ctk.CTkButton(
            actions, text="Hide panel", width=104, height=36, font=self.ui_font,
            command=self.toggle_sidebar,
        )
        self.sidebar_topbar_btn.pack(side="left", padx=4)

        self.file_btn = ctk.CTkButton(
            actions, text="📁 File", width=82, height=36, font=self.ui_font,
            command=self.show_file_menu,
        )
        self.file_btn.pack(side="left", padx=4)

        self.report_btn = ctk.CTkButton(
            actions, text="📊 Report", width=96, height=36, font=self.ui_font,
            command=self.open_tool_report,
        )
        self.report_btn.pack(side="left", padx=4)

        self.settings_btn = ctk.CTkButton(
            actions, text="⚙", width=44, height=36, font=self.ui_font_lg,
            command=self.open_settings,
        )
        self.settings_btn.pack(side="left", padx=4)

        ToolTip(self.wordlist_btn, "Add endpoints or push my-own-wordlist.txt to GitHub")
        ToolTip(self.sidebar_topbar_btn, "Show or hide scan controls and pipeline (Ctrl+B)")
        ToolTip(self.file_btn, "Import, export, save/load sessions")
        ToolTip(self.report_btn, "Tool discovery report — counts per tool")
        ToolTip(self.settings_btn, "Settings — profile, tools, API keys, theme")

        self.file_menu = Menu(self, tearoff=0)
        self.file_menu.add_command(label="Choose scan folder...", command=self.choose_scan_workspace)
        self.file_menu.add_command(label="Load latest from scan folder...", command=self.load_latest_workspace_scan)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Import hosts...", command=self.import_hosts_file)
        self.file_menu.add_command(label="Import scan export...", command=self.import_scan_export_file)
        self.file_menu.add_command(label="Add findings manually...", command=self.open_manual_add_dialog)
        self.file_menu.add_command(label="Tool report...", command=self.open_tool_report)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Save session...", command=self.save_session_file)
        self.file_menu.add_command(label="Load session...", command=self.load_session_file)
        self.file_menu.add_command(label="New Scan (save previous)...", command=self.start_new_scan_thread)
        self.file_menu.add_command(label="Diff sessions...", command=self.diff_session_files)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Toggle sidebar panel", command=self.toggle_sidebar)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Export TXT...", command=self.save_as_txt)
        self.file_menu.add_command(label="Export Excel...", command=self.save_as_excel)
        self.file_menu.add_command(label="Export HTML report...", command=self.save_as_html)

    def toggle_wordlist_panel(self):
        if self._wordlist_panel and self._wordlist_panel.winfo_exists():
            self._close_wordlist_panel()
            return
        self._open_wordlist_panel()

    def _close_wordlist_panel(self):
        panel = getattr(self, "_wordlist_panel", None)
        if panel and panel.winfo_exists():
            panel.destroy()
        self._wordlist_panel = None

    def _open_wordlist_panel(self):
        self._close_wordlist_panel()
        ensure_wordlist_files()

        panel = ctk.CTkToplevel(self)
        self._wordlist_panel = panel
        panel.overrideredirect(True)
        panel.attributes("-topmost", True)
        panel.configure(fg_color=("#2b2b2b", "#2b2b2b"))

        shell = ctk.CTkFrame(panel, corner_radius=10, border_width=1, border_color="#3d3d3d")
        shell.pack(fill="both", expand=True)
        body = ctk.CTkFrame(shell, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=14, pady=12)

        header = ctk.CTkFrame(body, fg_color="transparent")
        header.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(header, text="My wordlist", font=FONT_SECTION).pack(side="left")
        ctk.CTkButton(
            header, text="✕", width=28, height=28, font=self.ui_font_sm,
            fg_color="transparent", hover_color="#3d3d3d",
            command=self._close_wordlist_panel,
        ).pack(side="right")

        ctk.CTkLabel(
            body,
            text="Saves to my-own-wordlist.txt and common.txt",
            font=FONT_SM, text_color="#888888", anchor="w",
        ).pack(fill="x", pady=(0, 8))

        entry = ctk.CTkEntry(
            body, placeholder_text="https://example.com/path or api.example.com",
            font=self.ui_font, height=36,
        )
        entry.pack(fill="x", pady=(0, 8))
        selected = self._selection_endpoint()
        if selected:
            entry.insert(0, selected)

        btn_row = ctk.CTkFrame(body, fg_color="transparent")
        btn_row.pack(fill="x", pady=(0, 6))
        btn_row.grid_columnconfigure(0, weight=1)
        btn_row.grid_columnconfigure(1, weight=1)

        def submit_add():
            value = entry.get().strip()
            if not value:
                self._wordlist_status_var.set("Enter an endpoint first.")
                self._set_wordlist_status_color("warn")
                return
            if endpoint_in_wordlist(value):
                shown = normalize_endpoint(value) or value
                self._wordlist_status_var.set(f"Duplicate — already in my-own-wordlist.txt: {shown}")
                self._set_wordlist_status_color("warn")
                return
            self._append_to_wordlists([value], "Add endpoint", notify="panel")
            entry.delete(0, "end")
            entry.focus_set()

        add_btn = ctk.CTkButton(
            btn_row, text="Add endpoint", font=self.ui_font, height=34,
            command=submit_add,
        )
        add_btn.grid(row=0, column=0, sticky="ew", padx=(0, 4))

        push_btn = ctk.CTkButton(
            btn_row, text="Push to GitHub", font=self.ui_font, height=34,
            fg_color="#1f538d", hover_color="#14375e",
            command=lambda: self.push_wordlist_to_github_now(notify="panel"),
        )
        push_btn.grid(row=0, column=1, sticky="ew", padx=(4, 0))

        status = ctk.CTkLabel(
            body, textvariable=self._wordlist_status_var,
            font=FONT_SM, text_color="#9cdc9c", anchor="w", wraplength=280, justify="left",
        )
        status.pack(fill="x", pady=(4, 0))
        self._wordlist_status_label = status
        self._wordlist_status_var.set("Select a row, then paste or edit the endpoint above.")

        entry.bind("<Return>", lambda _e: submit_add())
        panel.bind("<Escape>", lambda _e: self._close_wordlist_panel())

        panel.update_idletasks()
        panel_w, panel_h = 320, 190
        btn_x = self.wordlist_btn.winfo_rootx()
        btn_y = self.wordlist_btn.winfo_rooty() + self.wordlist_btn.winfo_height() + 4
        screen_w = panel.winfo_screenwidth()
        if btn_x + panel_w > screen_w - 8:
            btn_x = max(8, screen_w - panel_w - 8)
        panel.geometry(f"{panel_w}x{panel_h}+{btn_x}+{btn_y}")
        panel.after(80, entry.focus_set)

    def show_file_menu(self):
        x = self.file_btn.winfo_rootx()
        y = self.file_btn.winfo_rooty() + self.file_btn.winfo_height()
        self.file_menu.tk_popup(x, y)

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=300, corner_radius=15)
        self.sidebar.grid(row=1, column=0, sticky="ns", padx=10, pady=10)

        header_row = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        header_row.pack(fill="x", padx=10, pady=(16, 8))
        ctk.CTkLabel(header_row, text="RECON ENGINE", font=FONT_BRAND).pack(side="left")
        self.sidebar_collapse_btn = ctk.CTkButton(
            header_row, text="◀", width=28, height=28, font=self.ui_font_sm,
            fg_color="#333333", hover_color="#444444", command=self.toggle_sidebar,
        )
        self.sidebar_collapse_btn.pack(side="right")
        ToolTip(self.sidebar_collapse_btn, "Hide scan panel")

        self.target_entry = ctk.CTkEntry(
            self.sidebar, placeholder_text="Primary target domain", font=self.ui_font, height=36,
        )
        self.target_entry.pack(pady=6, padx=10, fill="x")

        ctk.CTkLabel(self.sidebar, text="Target queue (one per line)", font=FONT_SM).pack(anchor="w", padx=12)
        self.queue_box = ctk.CTkTextbox(self.sidebar, height=68, font=self.ui_font)
        self.queue_box.pack(pady=4, padx=10, fill="x")

        self.drop_hint = ctk.CTkLabel(
            self.sidebar,
            text="Drop .txt file here to load targets",
            font=FONT_XS,
            text_color="#666666",
        )
        self.drop_hint.pack(anchor="w", padx=12, pady=(0, 4))

        self.workspace_label = ctk.CTkLabel(
            self.sidebar,
            text="",
            font=FONT_XS,
            text_color="#666666",
            wraplength=260,
            justify="left",
        )
        self.workspace_label.pack(anchor="w", padx=12, pady=(0, 4))
        self._update_workspace_label()

        btn_row = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        btn_row.pack(pady=4, padx=10, fill="x")
        self.start_btn = ctk.CTkButton(
            btn_row, text="Start Scan", command=self.start_scan_thread, font=self.ui_font, height=36,
        )
        self.start_btn.pack(side="left", expand=True, fill="x", padx=(0, 4))
        self.resume_btn = ctk.CTkButton(
            btn_row, text="Resume", command=self.start_resume_scan_thread,
            fg_color="#1b5e20", hover_color="#2e7d32", width=78, height=36,
            font=self.ui_font, state="disabled",
        )
        self.resume_btn.pack(side="left", padx=(0, 4))
        self.stop_btn = ctk.CTkButton(
            btn_row, text="Stop", command=self.stop_scan, fg_color="#8B0000", width=68, height=36,
            font=self.ui_font, state="disabled",
        )
        self.stop_btn.pack(side="right")

        self.new_scan_btn = ctk.CTkButton(
            self.sidebar, text="New Scan", command=self.start_new_scan_thread,
            fg_color="#1565C0", hover_color="#1976D2", font=self.ui_font, height=34,
        )
        self.new_scan_btn.pack(pady=(0, 4), padx=10, fill="x")

        self.skip_btn = ctk.CTkButton(
            self.sidebar, text="Skip Current Tool", command=self.skip_current_tool,
            fg_color="#5a3a00", hover_color="#7a4f00", state="disabled", font=self.ui_font, height=36,
        )
        self.skip_btn.pack(pady=4, padx=10, fill="x")

        ToolTip(self.start_btn, "Start scan (Ctrl+Enter)")
        ToolTip(self.new_scan_btn, "Save current scan to workspace and start fresh (Ctrl+Shift+N)")
        ToolTip(self.resume_btn, "Continue imported partial scan from last tool")
        ToolTip(self.stop_btn, "Stop entire scan (Esc)")
        ToolTip(self.skip_btn, "Skip the currently running tool")
        ToolTip(self.target_entry, "Primary target domain")
        ToolTip(self.queue_box, "Extra targets, one per line. Or drop a .txt file.")

        self.sidebar_scroll = ctk.CTkScrollableFrame(
            self.sidebar, height=440, label_text="Pipeline", label_font=FONT_SECTION,
            **CTK_SCROLLBAR_KWARGS,
        )
        self.sidebar_scroll.pack(pady=8, padx=5, fill="both", expand=True)

        self.tools = {t: "Pending" for t in TOOL_NAMES}
        self.tool_counts = {t: 0 for t in TOOL_NAMES}
        self.tool_rows = {}
        self.tool_group_headers = {}
        self.tool_group_bodies = {}
        self._build_tool_status_panel()

        self._bind_ctk_scrollable(self.sidebar_scroll)

    def _build_tool_status_panel(self):
        summary = ctk.CTkFrame(self.sidebar_scroll, fg_color="#1e2229", corner_radius=8)
        summary.pack(fill="x", padx=4, pady=(0, 8))
        self.tool_summary_label = ctk.CTkLabel(
            summary, text="0 / 0 ready", font=FONT_SM, text_color="#aab4c0",
        )
        self.tool_summary_label.pack(anchor="w", padx=10, pady=(8, 2))
        self.tool_summary_bar = ctk.CTkProgressBar(summary, height=8, corner_radius=4)
        self.tool_summary_bar.pack(fill="x", padx=10, pady=(0, 8))
        self.tool_summary_bar.set(0)

        self.tool_group_expanded = {}
        for group_name, tools in TOOL_GROUPS:
            section = ctk.CTkFrame(self.sidebar_scroll, fg_color="transparent")
            section.pack(fill="x", padx=2, pady=(0, 6))

            body = ctk.CTkFrame(section, fg_color="transparent")
            self.tool_group_expanded[group_name] = True

            header = ctk.CTkButton(
                section,
                text=f"▾ {group_name}  (0/{len(tools)})",
                font=FONT_SM,
                height=30,
                anchor="w",
                fg_color="#252932",
                hover_color="#2f3540",
                text_color="#cfd8dc",
            )
            header.pack(fill="x")

            def toggle(g=group_name, b=body, h=header):
                open_state = not self.tool_group_expanded.get(g, True)
                self.tool_group_expanded[g] = open_state
                if open_state:
                    b.pack(fill="x", padx=4, pady=(2, 0))
                else:
                    b.pack_forget()
                self._refresh_tool_summary()

            header.configure(command=toggle)
            self.tool_group_headers[group_name] = header
            self.tool_group_bodies[group_name] = body
            body.pack(fill="x", padx=4, pady=(2, 0))

            for tool in tools:
                row = ctk.CTkFrame(body, fg_color="#2b2f38", corner_radius=6, height=32)
                row.pack(fill="x", pady=2)
                row.pack_propagate(False)

                accent = ctk.CTkFrame(row, width=4, corner_radius=2, fg_color="#4a5060")
                accent.pack(side="left", fill="y", padx=(0, 6), pady=4)

                badge = ctk.CTkLabel(
                    row, text="···", width=22, font=("Arial", 13, "bold"), text_color="#666",
                )
                badge.pack(side="left", padx=(0, 4))

                name = ctk.CTkLabel(
                    row, text=shorten_tool_name(tool), font=FONT_SM, text_color="#9aa3b2", anchor="w",
                )
                name.pack(side="left", fill="x", expand=True)

                count = ctk.CTkLabel(
                    row, text="", width=36, font=FONT_XS, text_color="#7ec8e3",
                )
                count.pack(side="right", padx=8)

                rerun_btn = ctk.CTkButton(
                    row,
                    text="↻",
                    width=28,
                    height=26,
                    font=self.ui_font_sm,
                    fg_color="#1f538d",
                    hover_color="#2a6cae",
                    command=lambda t=tool: self.rerun_tool(t),
                )
                rerun_btn.pack(side="right", padx=(0, 6))
                ToolTip(rerun_btn, f"Re-run {tool}")

                ToolTip(row, tool)
                self.tool_rows[tool] = {
                    "row": row,
                    "accent": accent,
                    "badge": badge,
                    "name": name,
                    "count": count,
                    "group": group_name,
                }

        self._refresh_tool_summary()

    def _refresh_tool_summary(self):
        if not hasattr(self, "tool_summary_label"):
            return
        active = self.selected_tools if self.selected_tools else set(TOOL_NAMES)
        relevant = [t for t in TOOL_NAMES if t in active]
        total = len(relevant) or len(TOOL_NAMES)
        done = sum(
            1 for t in relevant
            if self.tools.get(t) in ("Done", "Skipped", "Error")
        )
        running = next((t for t in relevant if self.tools.get(t) == "Running"), "")
        self.tool_summary_label.configure(
            text=f"{done}/{total} complete" + (f"  ·  {shorten_tool_name(running, 16)}" if running else ""),
        )
        self.tool_summary_bar.set(done / total if total else 0)

        for group_name, tools in TOOL_GROUPS:
            header = self.tool_group_headers.get(group_name)
            if not header:
                continue
            group_tools = [t for t in tools if t in active]
            if not group_tools:
                continue
            g_done = sum(
                1 for t in group_tools
                if self.tools.get(t) in ("Done", "Skipped", "Error")
            )
            g_run = any(self.tools.get(t) == "Running" for t in group_tools)
            prefix = "▾ " if self.tool_group_expanded.get(group_name, True) else "▸ "
            marker = " ●" if g_run else ""
            header.configure(text=f"{prefix}{group_name}  ({g_done}/{len(group_tools)}){marker}")

    def _scroll_tool_into_view(self, tool):
        row = self.tool_rows.get(tool, {}).get("row")
        if not row:
            return
        try:
            canvas = self.sidebar_scroll._parent_canvas
            inner = self.sidebar_scroll._parent_frame
            canvas.update_idletasks()
            y = row.winfo_y()
            total = max(inner.winfo_height(), 1)
            view = max(canvas.winfo_height(), 1)
            target = (y - view * 0.3) / max(total - view, 1)
            canvas.yview_moveto(max(0.0, min(1.0, target)))
        except Exception:
            pass

    def _build_main(self):
        self.main = ctk.CTkFrame(self, corner_radius=15)
        self.main.grid(row=1, column=1, sticky="nsew", padx=10, pady=10)
        self.main.grid_rowconfigure(4, weight=1)
        self.main.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(self.main)
        header.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 4))
        self.status_label = ctk.CTkLabel(header, text="Status: Idle", font=FONT_XL)
        self.status_label.pack(side="left", padx=8)
        self.profile_label = ctk.CTkLabel(
            header, text=f"Profile: {self.profile_var.get()}", font=FONT_MD, text_color="#888",
        )
        self.profile_label.pack(side="left", padx=8)
        self.scan_time_label = ctk.CTkLabel(
            header, text="", font=FONT_SM, text_color="#7ec8e3",
        )
        self.scan_time_label.pack(side="left", padx=8)
        self.active_tool = ctk.CTkLabel(header, text="Active: None", font=FONT_LG)
        self.active_tool.pack(side="right", padx=8)

        prog = ctk.CTkFrame(self.main, fg_color="transparent")
        prog.grid(row=1, column=0, sticky="ew", padx=10)
        self.progress = ctk.CTkProgressBar(prog)
        self.progress.pack(fill="x", pady=2)
        self.progress.set(0)
        self.progress_label = ctk.CTkLabel(prog, text="Ready", font=FONT_SM, text_color="#aaa")
        self.progress_label.pack(anchor="w")

        self._build_stats_cards()

        nav = ctk.CTkFrame(self.main, fg_color="transparent")
        nav.grid(row=3, column=0, sticky="ew", padx=10, pady=6)
        self.view_switch = ctk.CTkSegmentedButton(
            nav, values=self.VIEWS, command=self.switch_view,
            font=self.ui_font, height=34,
        )
        self.view_switch.set(self.VIEWS[0])
        self.view_switch.pack(side="left")

        filt = ctk.CTkFrame(nav, fg_color="transparent")
        filt.pack(side="right")
        self.add_btn = ctk.CTkButton(
            filt, text="+ Add", width=72, height=34, font=self.ui_font,
            command=self.open_manual_add_dialog,
        )
        self.add_btn.pack(side="left", padx=4)
        ToolTip(self.add_btn, "Manually add subdomains, URLs, IPs, or buckets")

        self.search_scope = ctk.CTkOptionMenu(
            filt,
            values=["All types", *self.VIEWS],
            command=self._on_search_scope_change,
            width=130, font=self.ui_font, height=34,
        )
        self.search_scope.set("All types")
        self.search_scope.pack(side="left", padx=4)
        ToolTip(self.search_scope, "Limit search to subdomains, URLs, IPs, or buckets")

        self.filter_entry = ctk.CTkEntry(
            filt, placeholder_text="Search endpoints, subdomains, IPs, tools…",
            width=280, font=self.ui_font, height=34,
        )
        self.filter_entry.pack(side="left", padx=4)
        self.filter_entry.bind("<KeyRelease>", lambda _e: self._on_search_changed())
        self.filter_entry.bind("<Return>", lambda _e: self._on_search_changed(jump_to_best=True))

        self.clear_search_btn = ctk.CTkButton(
            filt, text="✕", width=36, height=34, fg_color="#444444", font=self.ui_font,
            command=self.clear_search,
        )
        self.clear_search_btn.pack(side="left", padx=(0, 4))
        ToolTip(self.clear_search_btn, "Clear search")

        self.filter_status = ctk.CTkOptionMenu(
            filt, values=["All", "Live only", "200", "403", "Has note", "Takeover", "Params only"],
            command=lambda _v: self._on_search_changed(), width=120, font=self.ui_font, height=34,
        )
        self.filter_status.pack(side="left", padx=4)

        self.search_result_label = ctk.CTkLabel(
            filt, text="", font=FONT_SM, text_color="#888888", width=110,
        )
        self.search_result_label.pack(side="left", padx=4)

        ToolTip(self.filter_entry, "Search value, path, status, tool, IP, notes (Ctrl+F)")
        ToolTip(self.filter_status, "Filter by status or type")

        self.table_frame = ctk.CTkFrame(self.main)
        self.table_frame.grid(row=4, column=0, sticky="nsew", padx=10)
        self.table_frame.grid_rowconfigure(0, weight=1)
        self.table_frame.grid_columnconfigure(0, weight=1)

        self.log_bar = ctk.CTkFrame(self.main, fg_color="transparent")
        self.log_bar.grid(row=5, column=0, sticky="ew", padx=10, pady=(6, 0))
        ctk.CTkLabel(self.log_bar, text="Logs", font=FONT_SECTION).pack(side="left", padx=4)
        self.log_toggle_btn = ctk.CTkButton(
            self.log_bar, text="Hide logs", width=100, height=30, font=self.ui_font_sm,
            command=self.toggle_logs_panel,
        )
        self.log_toggle_btn.pack(side="right", padx=4)

        self.logs = ctk.CTkTextbox(self.main, height=120, font=self.ui_font)
        self.logs.grid(row=6, column=0, sticky="ew", padx=10, pady=(4, 10))
        ToolTip(self.log_toggle_btn, "Show or hide the log panel")

    def _close_table_context_menu(self):
        panel = getattr(self, "_table_context_menu", None)
        if panel and panel.winfo_exists():
            panel.destroy()
        self._table_context_menu = None
        dismiss = getattr(self, "_table_context_dismiss_bind", None)
        if dismiss:
            try:
                self.unbind("<ButtonPress-1>", dismiss)
                self.unbind("<ButtonPress-3>", dismiss)
            except Exception:
                pass
            self._table_context_dismiss_bind = None

    def _open_table_context_menu(self, item, x_root, y_root):
        self._close_table_context_menu()

        panel = ctk.CTkToplevel(self)
        self._table_context_menu = panel
        panel.withdraw()
        panel.overrideredirect(True)
        panel.attributes("-topmost", True)
        panel.configure(fg_color="#252932")
        panel.resizable(False, False)

        shell = ctk.CTkFrame(
            panel, corner_radius=10, border_width=1,
            border_color="#4a5568", fg_color="#252932",
        )
        shell.pack(fill="both", expand=True, padx=1, pady=1)

        def run_action(callback):
            self._close_table_context_menu()
            callback()

        ctk.CTkButton(
            shell, text="Add note", anchor="w", height=36, font=self.ui_font,
            fg_color="#2f3540", hover_color="#1f538d", text_color="#e8eaed",
            command=lambda: run_action(lambda: self.edit_note_for_item(item)),
        ).pack(fill="x", padx=8, pady=(8, 4))

        ctk.CTkFrame(shell, height=1, fg_color="#3d4654").pack(fill="x", padx=10, pady=2)

        ctk.CTkButton(
            shell, text="Remove", anchor="w", height=36, font=self.ui_font,
            fg_color="#2f3540", hover_color="#5c1a1a", text_color="#ff8a80",
            command=lambda: run_action(self.remove_selection),
        ).pack(fill="x", padx=8, pady=(4, 8))

        panel.bind("<Escape>", lambda _e: self._close_table_context_menu())

        menu_w, menu_h = 200, 96
        screen_w = panel.winfo_screenwidth()
        screen_h = panel.winfo_screenheight()
        pos_x = max(8, min(x_root, screen_w - menu_w - 8))
        pos_y = max(8, min(y_root, screen_h - menu_h - 8))
        panel.geometry(f"{menu_w}x{menu_h}+{pos_x}+{pos_y}")
        panel.update_idletasks()
        panel.deiconify()
        panel.lift()
        panel.focus_force()

        def dismiss_outside(event):
            menu = getattr(self, "_table_context_menu", None)
            if not menu or not menu.winfo_exists():
                return
            mx, my = menu.winfo_rootx(), menu.winfo_rooty()
            mw, mh = menu.winfo_width(), menu.winfo_height()
            if mx <= event.x_root <= mx + mw and my <= event.y_root <= my + mh:
                return
            self._close_table_context_menu()

        self._table_context_dismiss_bind = dismiss_outside
        self.after(200, lambda: self.bind("<ButtonPress-1>", dismiss_outside, add="+"))
        self.after(200, lambda: self.bind("<ButtonPress-3>", dismiss_outside, add="+"))

    def _short_tool_label(self, tool, max_len=6):
        text = str(tool or "").strip()
        if len(text) <= max_len:
            return text
        return f"{text[: max_len - 1]}…"

    def _short_status_label(self, status, max_len=6):
        return self._short_tool_label(status, max_len=max_len)

    def _probe_cell(self, value):
        text = str(value or "").strip()
        return text if text else "—"

    def _format_probe_details(self, data, *, found_by=None):
        if found_by is None:
            found_by = str(data.get("tools") or "").strip()
            if not found_by and data.get("sources") is not None:
                found_by = self._host_display_tool(data)
        status = self._probe_cell(data.get("status"))
        clen = self._probe_cell(data.get("content_length"))
        if clen != "—" and clen.isdigit():
            clen = f"{clen} B"
        title = self._probe_cell(data.get("title"))
        tech = self._probe_cell(data.get("tech"))
        found = self._probe_cell(found_by)
        return f"{found} · {clen} · {title} · {tech} · {status}"

    def _table_column_width(self, col):
        if col == "shot":
            return 48
        if col == "tools":
            return 88
        if col == "probe":
            return 320
        if col == "status":
            return 56
        if col == "value":
            return 320
        if col in ("note", "related"):
            return 120
        return 80

    def _table_column_stretch(self, col):
        return col in ("value", "probe")

    def _table_column_wrap(self, col):
        return col in ("value", "note", "related", "probe")

    def _table_event_row(self, event):
        tree = self.active_tree()
        if hasattr(tree, "row_at_event"):
            return tree.row_at_event(event)
        return tree.identify_row(event.y)

    def _table_event_column(self, event):
        tree = self.active_tree()
        if hasattr(tree, "column_at_event"):
            return tree.column_at_event(event)
        return tree.identify_column(event.x)

    def _table_event_region(self, event):
        tree = self.active_tree()
        if hasattr(tree, "region_at_event"):
            return tree.region_at_event(event)
        return tree.identify_region(event.x, event.y)

    def _build_stats_cards(self):
        self.stats_row = ctk.CTkFrame(self.main, fg_color="transparent")
        self.stats_row.grid(row=2, column=0, sticky="ew", padx=10, pady=4)
        specs = [
            ("subdomains", "Subdomains", "#4fc3f7"),
            ("live", "Live hosts", "#3ddc84"),
            ("urls", "URLs", "#ffb74d"),
            ("ips", "IPs", "#ce93d8"),
            ("buckets", "Buckets", "#ff8a65"),
            ("sensitive", "Sensitive", "#ef5350"),
            ("js", "JS files", "#81c784"),
            ("takeovers", "Takeovers", "#ff5252"),
        ]
        for key, title, color in specs:
            card = ctk.CTkFrame(self.stats_row, corner_radius=8)
            card.pack(side="left", fill="x", expand=True, padx=4)
            ctk.CTkLabel(card, text=title, font=FONT_STATS_LABEL, text_color="#999999").pack(
                anchor="w", padx=10, pady=(6, 0),
            )
            lbl = ctk.CTkLabel(card, text="0", font=FONT_STATS_NUM, text_color=color)
            lbl.pack(anchor="w", padx=10, pady=(0, 6))
            self._stats_labels[key] = lbl

    def _collect_stats(self):
        live = sum(
            1 for data in self.hosts.values()
            if str(data.get("status", "")).strip() not in ("-", "")
        )
        takeovers = sum(
            1 for data in self.hosts.values()
            if "takeover" in f"{data.get('status', '')} {data.get('note', '')}".lower()
        )
        return {
            "subdomains": len(self.hosts),
            "live": live,
            "urls": len(self.urls),
            "ips": len(self.ips),
            "buckets": len(self.buckets),
            "sensitive": len(self.sensitive),
            "js": len(self.js_files),
            "takeovers": takeovers,
        }

    def _get_filter_state(self):
        query = ""
        status_f = "All"
        scope = "All types"
        if hasattr(self, "filter_entry"):
            query = self.filter_entry.get().strip().lower()
        if hasattr(self, "filter_status"):
            status_f = self.filter_status.get()
        if hasattr(self, "search_scope"):
            scope = self.search_scope.get()
        return query, status_f, scope

    def _is_filter_active(self):
        query, status_f, _scope = self._get_filter_state()
        return bool(query) or status_f != "All"

    def _matches_search(self, blob, query):
        if not query:
            return True
        text = str(blob or "").lower()
        return all(term in text for term in query.split())

    def _host_search_blob(self, host, data):
        return " ".join([
            host,
            self._host_display_tool(data),
            str(data.get("status", "")),
            str(data.get("ip", "")),
            str(data.get("content_length", "")),
            str(data.get("title", "")),
            str(data.get("tech", "")),
            str(data.get("note", "")),
        ])

    def _url_search_blob(self, url, data):
        return " ".join([
            url,
            str(data.get("tools", "")),
            str(data.get("status", "")),
            str(data.get("content_length", "")),
            str(data.get("title", "")),
            str(data.get("tech", "")),
            str(data.get("note", "")),
        ])

    def _ip_search_blob(self, ip, related, data):
        return " ".join([
            ip,
            related,
            str(data.get("tools", "")),
            str(data.get("status", "")),
            str(data.get("content_length", "")),
            str(data.get("title", "")),
            str(data.get("tech", "")),
            str(data.get("note", "")),
        ])

    def _passes_status_filter(self, status_f, data, *, is_host=False):
        status = str(data.get("status", ""))
        note = str(data.get("note", ""))
        if status_f == "All":
            return True
        if status_f == "Live only":
            return status.strip() not in ("-", "")
        if status_f in ("200", "403"):
            return status == status_f
        if status_f == "Has note":
            return bool(note.strip())
        if status_f == "Takeover":
            return "takeover" in f"{status} {note}".lower()
        if status_f == "Params only":
            return data.get("tools") == "URL Param Filter" or status.lower() == "param"
        return True

    def _passes_filter(self, host, data, query, status_f):
        if not self._matches_search(self._host_search_blob(host, data), query):
            return False
        return self._passes_status_filter(status_f, data, is_host=True)

    def _passes_url_filter(self, url, data, query, status_f):
        if not self._matches_search(self._url_search_blob(url, data), query):
            return False
        return self._passes_status_filter(status_f, data)

    def _passes_ip_filter(self, ip, related, data, query, status_f):
        if not self._matches_search(self._ip_search_blob(ip, related, data), query):
            return False
        if status_f == "Has note":
            return bool(str(data.get("note", "")).strip())
        if status_f in ("Live only", "200", "403", "Takeover", "Params only"):
            return False
        return True

    def _passes_bucket_filter(self, url, data, query, status_f):
        if not self._matches_search(self._url_search_blob(url, data), query):
            return False
        return self._passes_status_filter(status_f, data)

    def _passes_sensitive_filter(self, url, data, query, status_f):
        if not self._matches_search(self._url_search_blob(url, data), query):
            return False
        if status_f == "Has note":
            return bool(str(data.get("note", "")).strip())
        if status_f in ("Live only", "200", "403", "Takeover", "Params only"):
            if status_f == "Params only":
                return str(data.get("status", "")).lower() == "params"
            return False
        return self._passes_status_filter(status_f, data)

    def _passes_js_filter(self, url, data, query, status_f):
        if not self._matches_search(self._url_search_blob(url, data), query):
            return False
        if status_f == "Has note":
            return bool(str(data.get("note", "")).strip())
        if status_f == "Params only":
            return False
        if status_f in ("Live only", "403", "Takeover"):
            return False
        if status_f == "200":
            return str(data.get("status", "")).lower() in ("200", "js", "secret")
        return self._passes_status_filter(status_f, data)

    def _filtered_counts(self):
        query, status_f, _scope = self._get_filter_state()
        return {
            "subdomains": sum(
                1 for host, data in self.hosts.items()
                if self._passes_filter(host, data, query, status_f)
            ),
            "urls": sum(
                1 for url, data in self.urls.items()
                if self._passes_url_filter(url, data, query, status_f)
            ),
            "ips": sum(
                1 for (ip, related), data in self.ips.items()
                if self._passes_ip_filter(ip, related, data, query, status_f)
            ),
            "buckets": sum(
                1 for url, data in self.buckets.items()
                if self._passes_bucket_filter(url, data, query, status_f)
            ),
            "sensitive": sum(
                1 for url, data in self.sensitive.items()
                if self._passes_sensitive_filter(url, data, query, status_f)
            ),
            "js": sum(
                1 for url, data in self.js_files.items()
                if self._passes_js_filter(url, data, query, status_f)
            ),
        }

    def _on_search_scope_change(self, _choice=None):
        scope = self.search_scope.get()
        if scope != "All types" and scope in self.VIEWS:
            self._shortcut_view(scope)
        else:
            self._on_search_changed()

    def _on_search_changed(self, jump_to_best=False):
        query, status_f, scope = self._get_filter_state()
        if jump_to_best and query and scope == "All types":
            counts = self._filtered_counts()
            best_view = max(
                self.VIEWS,
                key=lambda v: counts[{
                    "Subdomains": "subdomains", "URLs": "urls", "IPs": "ips",
                    "Buckets": "buckets", "Sensitive": "sensitive", "JS": "js",
                }[v]],
            )
            key_map = {
                "Subdomains": "subdomains", "URLs": "urls", "IPs": "ips",
                "Buckets": "buckets", "Sensitive": "sensitive", "JS": "js",
            }
            if counts[key_map[best_view]] > 0:
                if best_view != self._current_view:
                    self._shortcut_view(best_view)
                    return
        self.refresh_current_view()

    def clear_search(self):
        self.filter_entry.delete(0, "end")
        self.filter_status.set("All")
        self.search_scope.set("All types")
        self._on_search_changed()

    def focus_filter(self):
        self.filter_entry.focus()
        self.filter_entry.select_range(0, "end")

    def _update_stats_display(self):
        stats = self._collect_stats()
        filtered = self._filtered_counts()
        active = self._is_filter_active()
        labels = {
            "subdomains": ("Subdomains", stats["subdomains"], filtered["subdomains"]),
            "live": ("Live hosts", stats["live"], None),
            "urls": ("URLs", stats["urls"], filtered["urls"]),
            "ips": ("IPs", stats["ips"], filtered["ips"]),
            "buckets": ("Buckets", stats["buckets"], filtered["buckets"]),
            "sensitive": ("Sensitive", stats["sensitive"], filtered["sensitive"]),
            "js": ("JS files", stats["js"], filtered["js"]),
            "takeovers": ("Takeovers", stats["takeovers"], None),
        }
        for key, lbl in self._stats_labels.items():
            _title, total, match = labels[key]
            if active and match is not None and match != total:
                new_text = f"{match}/{total}"
            else:
                new_text = str(total)
            if self._stats_text_cache.get(key) == new_text:
                continue
            self._stats_text_cache[key] = new_text
            lbl.configure(text=new_text)

    def _tab_labels(self):
        return list(self.VIEWS)

    def _view_from_label(self, label):
        for view in self.VIEWS:
            if label == view or str(label).startswith(f"{view} ("):
                return view
        return label

    def update_window_title(self):
        base = "Recon Intelligence Dashboard"
        if self.current_target:
            self.title(f"{base} — {self.current_target}")
        elif self.scanning:
            self.title(f"{base} — Scanning…")
        else:
            self.title(base)

    def toggle_logs_panel(self):
        self.logs_visible = not self.logs_visible
        if self.logs_visible:
            self.logs.grid(row=6, column=0, sticky="ew", padx=10, pady=(4, 10))
            self.log_toggle_btn.configure(text="Hide logs")
        else:
            self.logs.grid_remove()
            self.log_toggle_btn.configure(text="Show logs")

    def toggle_sidebar(self):
        self.sidebar_visible = not self.sidebar_visible
        if self.sidebar_visible:
            self.sidebar.grid(row=1, column=0, sticky="ns", padx=10, pady=10)
            if hasattr(self, "sidebar_expand_strip"):
                self.sidebar_expand_strip.grid_remove()
            self.sidebar_topbar_btn.configure(text="Hide panel")
            self.sidebar_collapse_btn.configure(text="◀")
        else:
            self.sidebar.grid_remove()
            if not hasattr(self, "sidebar_expand_strip"):
                self.sidebar_expand_strip = ctk.CTkFrame(self, width=28, corner_radius=8)
                self.sidebar_expand_btn = ctk.CTkButton(
                    self.sidebar_expand_strip, text="▶", width=24, height=56, font=self.ui_font_sm,
                    fg_color="#333333", hover_color="#444444", command=self.toggle_sidebar,
                )
                self.sidebar_expand_btn.pack(padx=2, pady=8)
                ToolTip(self.sidebar_expand_btn, "Show scan panel")
            self.sidebar_expand_strip.grid(row=1, column=0, sticky="ns", padx=(4, 0), pady=10)
            self.sidebar_topbar_btn.configure(text="Show panel")

    def _setup_drag_drop(self):
        try:
            from tkinterdnd2 import DND_FILES

            widgets = [
                self,
                self.queue_box._textbox,
                self.target_entry._entry,
                self.sidebar,
            ]
            for widget in widgets:
                widget.drop_target_register(DND_FILES)
                widget.dnd_bind("<<Drop>>", self._on_file_drop)
            self.drop_hint.configure(text="Drop .txt file here to load targets")
        except Exception:
            self.drop_hint.configure(text="Install tkinterdnd2 for drag & drop (.txt)")

    def _on_file_drop(self, event):
        paths = self.tk.splitlist(event.data.strip())
        if paths:
            self._load_text_file_to_queue(paths[0])

    def _load_text_file_to_queue(self, path):
        file_path = Path(path)
        if not file_path.is_file() or file_path.suffix.lower() != ".txt":
            self.log(f"[DROP] Ignored — not a .txt file: {path}")
            return
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        domains = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
        if not domains:
            self.log(f"[DROP] No targets in {path}")
            return
        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, domains[0])
        self.queue_box.delete("1.0", "end")
        if len(domains) > 1:
            self.queue_box.insert("1.0", "\n".join(domains[1:]))
        self.log(f"[DROP] Loaded {len(domains)} targets from {file_path.name}")

    def _build_tables(self):
        self._tree_headings = {
            "shot": "📷", "value": "Host / URL / IP", "tools": "",
            "probe": "Found by · Length · Title · Tech · Status", "status": "", "ip": "IP",
            "related": "Related", "note": "",
        }
        self.tables = {}
        specs = {
            "Subdomains": ("shot", "value", "probe", "note"),
            "URLs": ("value", "tools", "status", "note"),
            "IPs": ("value", "probe", "related", "note"),
            "Buckets": ("value", "status", "tools", "note"),
            "Sensitive": ("value", "tools", "status", "note"),
            "JS": ("value", "tools", "status", "note"),
        }
        for view, cols in specs.items():
            frame = ctk.CTkFrame(self.table_frame)
            frame.grid(row=0, column=0, sticky="nsew")
            frame.grid_rowconfigure(0, weight=1)
            frame.grid_columnconfigure(0, weight=1)
            tree_host = ctk.CTkFrame(frame, fg_color="transparent")
            tree_host.grid(row=0, column=0, sticky="nsew")
            tree_host.grid_rowconfigure(0, weight=1)
            tree_host.grid_columnconfigure(0, weight=1)
            tree = WrapDataTable(
                tree_host,
                columns=cols,
                headings=self._tree_headings,
                col_width_fn=self._table_column_width,
                col_stretch_fn=self._table_column_stretch,
                col_wrap_fn=self._table_column_wrap,
                ui_font=self.ui_font,
                ui_font_sm=self.ui_font_sm,
            )
            tree.grid(row=0, column=0, sticky="nsew")
            for col in cols:
                tree.heading(
                    col,
                    text=self._tree_headings.get(col, col),
                    command=lambda c=col, v=view: self._sort_by(v, c),
                )
            tree.bind("<Button-1>", self._on_table_select, add="+")
            tree.bind("<ButtonRelease-1>", self.on_table_click)
            tree.bind("<Button-3>", self.show_context_menu)
            tree.bind("<Double-1>", self.on_double_click)
            self._bind_mousewheel(tree.scroll)
            self._bind_ctk_scrollable(tree.scroll)
            self.tables[view] = {"frame": frame, "tree": tree, "cols": cols}

        self._bind_mousewheel(self.logs)
        self._bind_mousewheel(self.queue_box)

    def _bind_mousewheel(self, widget):
        def scroll(event):
            delta = 0
            if hasattr(event, "delta") and event.delta:
                delta = -1 * int(event.delta / 120)
            elif getattr(event, "num", None) == 4:
                delta = -1
            elif getattr(event, "num", None) == 5:
                delta = 1
            if delta and hasattr(widget, "yview_scroll"):
                widget.yview_scroll(delta, "units")
            elif delta and hasattr(widget, "_textbox") and widget._textbox:
                widget._textbox.yview_scroll(delta, "units")

        widget.bind("<MouseWheel>", scroll, add="+")
        widget.bind("<Button-4>", scroll, add="+")
        widget.bind("<Button-5>", scroll, add="+")

    def _bind_ctk_scrollable(self, scroll_frame):
        canvas = scroll_frame._parent_canvas
        inner = scroll_frame._parent_frame
        state = {"bound": False}

        def wheel_delta(event):
            if getattr(event, "num", None) == 4:
                return -3
            if getattr(event, "num", None) == 5:
                return 3
            if getattr(event, "delta", 0):
                return int(-1 * (event.delta / 120)) * 3
            return 0

        def scroll(event):
            delta = wheel_delta(event)
            if delta:
                canvas.yview_scroll(delta, "units")
            return "break"

        def bind_wheel(_event=None):
            if state["bound"]:
                return
            state["bound"] = True
            self.bind_all("<MouseWheel>", scroll, add="+")
            self.bind_all("<Button-4>", scroll, add="+")
            self.bind_all("<Button-5>", scroll, add="+")

        def unbind_wheel(_event=None):
            self.after(80, _maybe_unbind)

        def _maybe_unbind():
            if not self._app_alive():
                return
            try:
                x, y = self.winfo_pointerxy()
                widget = self.winfo_containing(x, y)
            except (KeyError, TclError):
                widget = None
            if widget and _is_inside_scroll_area(widget):
                return
            if state["bound"]:
                state["bound"] = False
                self.unbind_all("<MouseWheel>")
                self.unbind_all("<Button-4>")
                self.unbind_all("<Button-5>")

        def _is_inside_scroll_area(widget):
            current = widget
            while current is not None:
                if current in (scroll_frame, canvas, inner):
                    return True
                current = getattr(current, "master", None)
            return False

        def bind_recursive(widget):
            widget.bind("<Enter>", bind_wheel, add="+")
            widget.bind("<Leave>", unbind_wheel, add="+")
            widget.bind("<MouseWheel>", scroll, add="+")
            widget.bind("<Button-4>", scroll, add="+")
            widget.bind("<Button-5>", scroll, add="+")
            for child in widget.winfo_children():
                bind_recursive(child)

        for target in (scroll_frame, canvas, inner):
            bind_recursive(target)

    def _bind_shortcuts(self):
        self.bind("<Control-f>", lambda _e: self.focus_filter())
        self.bind("<Control-F>", lambda _e: self.focus_filter())
        self.bind("<Control-Return>", lambda _e: self.start_scan_thread())
        self.bind("<Control-Shift-N>", lambda _e: self.start_new_scan_thread())
        self.bind("<Control-Shift-n>", lambda _e: self.start_new_scan_thread())
        self.bind("<Control-b>", lambda _e: self.toggle_sidebar())
        self.bind("<Control-B>", lambda _e: self.toggle_sidebar())
        self.bind("<Control-s>", lambda _e: self.save_session_file())
        self.bind("<Control-S>", lambda _e: self.save_session_file())
        self.bind("<Escape>", lambda _e: self.stop_scan())
        self.bind("<Control-d>", lambda _e: self.toggle_theme())
        self.bind("<Control-D>", lambda _e: self.toggle_theme())
        self.bind("<Control-l>", lambda _e: self.target_entry.focus())
        self.bind("<Control-1>", lambda _e: self._shortcut_view("Subdomains"))
        self.bind("<Control-2>", lambda _e: self._shortcut_view("URLs"))
        self.bind("<Control-3>", lambda _e: self._shortcut_view("IPs"))
        self.bind("<Control-4>", lambda _e: self._shortcut_view("Buckets"))
        self.bind("<Control-5>", lambda _e: self._shortcut_view("Sensitive"))
        self.bind("<Control-6>", lambda _e: self._shortcut_view("JS"))
        self.bind("<Control-n>", lambda _e: self.open_manual_add_dialog())
        self.bind("<Control-N>", lambda _e: self.open_manual_add_dialog())

    def _shortcut_view(self, view):
        self._current_view = view
        self.view_switch.set(view)
        self.switch_view(view)

    def _sort_by(self, view, col):
        state = self.sort_state[view]
        if state["col"] == col:
            state["reverse"] = not state["reverse"]
        else:
            state["col"] = col
            state["reverse"] = False
        tree = self.tables[view]["tree"]
        sort_col = state["col"]
        for c in self.tables[view]["cols"]:
            text = self._tree_headings.get(c, c)
            if c == sort_col:
                text += " ▼" if state["reverse"] else " ▲"
            tree.heading(c, text=text, command=lambda c2=c, v=view: self._sort_by(v, c2))
        self.refresh_current_view()

    def _sort_key(self, view, col, item):
        if view == "Subdomains":
            host, data = item
            return {
                "shot": "1" if data.get("screenshot") else "0",
                "value": host.lower(),
                "probe": " ".join([
                    str(data.get("status", "")),
                    str(data.get("content_length", "")),
                    str(data.get("title", "")).lower(),
                    str(data.get("tech", "")).lower(),
                    self._host_display_tool(data).lower(),
                    str(data.get("ip", "")),
                ]).lower(),
                "note": str(data.get("note", "")).lower(),
            }.get(col, host.lower())
        if view == "URLs":
            url, data = item
            return {
                "value": url.lower(),
                "tools": str(data.get("tools", "")).lower(),
                "status": str(data.get("status", "")),
                "note": str(data.get("note", "")).lower(),
            }.get(col, url.lower())
        if view == "IPs":
            key, data = item
            ip, related = key
            return {
                "value": ip.lower(),
                "probe": " ".join([
                    str(data.get("status", "")),
                    str(data.get("content_length", "")),
                    str(data.get("title", "")).lower(),
                    str(data.get("tech", "")).lower(),
                    str(data.get("tools", "")).lower(),
                ]).lower(),
                "related": related.lower(),
                "note": str(data.get("note", "")).lower(),
            }.get(col, ip.lower())
        if view == "Buckets":
            url, data = item
            return {
                "value": url.lower(),
                "status": str(data.get("status", "")),
                "tools": str(data.get("tools", "")).lower(),
                "note": str(data.get("note", "")).lower(),
            }.get(col, url.lower())
        if view == "Sensitive":
            url, data = item
            return {
                "value": url.lower(),
                "tools": str(data.get("tools", "")).lower(),
                "status": str(data.get("status", "")).lower(),
                "note": str(data.get("note", "")).lower(),
            }.get(col, url.lower())
        if view == "JS":
            url, data = item
            return {
                "value": url.lower(),
                "tools": str(data.get("tools", "")).lower(),
                "status": str(data.get("status", "")).lower(),
                "note": str(data.get("note", "")).lower(),
            }.get(col, url.lower())
        return str(item[0]).lower()

    def _row_tags(self, status="", row_index=0):
        tags = ["mono"]
        status_tag = status_row_tag(status)
        if status_tag:
            tags.append(status_tag)
        if row_index % 2:
            tags.append("zebra")
        return tuple(tags)

    def _insert_tree_row(self, tree, iid, values, status="", row_index=0):
        tags = self._row_tags(status, row_index)
        tree.insert("", "end", iid=iid, values=values, tags=tags)

    def _on_data_changed(self, refresh_view=True):
        self._update_stats_display()
        if not refresh_view:
            return
        if self.scanning:
            self._schedule_view_refresh()
        else:
            self._cancel_view_refresh()
            self.refresh_current_view()

    def _schedule_view_refresh(self):
        if self._view_refresh_job:
            return
        self._view_refresh_job = self.after(400, self._run_debounced_view_refresh)

    def _run_debounced_view_refresh(self):
        self._view_refresh_job = None
        self.refresh_current_view()

    def _cancel_view_refresh(self):
        if self._view_refresh_job:
            self.after_cancel(self._view_refresh_job)
            self._view_refresh_job = None

    def toggle_theme(self):
        mode = ctk.get_appearance_mode()
        new_mode = "light" if mode == "Dark" else "dark"
        ctk.set_appearance_mode(new_mode)
        cfg = load_config()
        cfg["appearance_mode"] = new_mode
        save_config(cfg)
        self.log(f"[UI] Theme: {new_mode}")

    def switch_view(self, view):
        view = self._view_from_label(view)
        self._current_view = view
        for name, data in self.tables.items():
            if name == view:
                data["frame"].grid()
            else:
                data["frame"].grid_remove()
        self.refresh_current_view()

    def active_tree(self):
        return self.tables[self._current_view]["tree"]

    def refresh_current_view(self):
        view = self._current_view
        tree = self.tables[view]["tree"]
        query, status_f, _scope = self._get_filter_state()
        sort = self.sort_state[view]
        items = []
        entries = []
        row_index = 0

        if view == "Subdomains":
            items = [(host, data) for host, data in self.hosts.items() if self._passes_filter(host, data, query, status_f)]
            if sort["col"]:
                items.sort(key=lambda it: self._sort_key(view, sort["col"], it), reverse=sort["reverse"])
            else:
                items.sort(key=lambda it: it[0].lower())
            for host, data in items:
                shot = "🖼" if data.get("screenshot") else "—"
                values = (
                    shot, host,
                    self._format_probe_details(data),
                    data.get("note", ""),
                )
                entries.append((host, values, self._row_tags(data.get("status", ""), row_index)))
                row_index += 1
        elif view == "URLs":
            items = [(url, data) for url, data in self.urls.items() if self._passes_url_filter(url, data, query, status_f)]
            if sort["col"]:
                items.sort(key=lambda it: self._sort_key(view, sort["col"], it), reverse=sort["reverse"])
            else:
                items.sort(key=lambda it: it[0].lower())
            for url, data in items:
                values = (
                    url,
                    self._short_tool_label(data.get("tools", ""), max_len=12),
                    self._short_status_label(data.get("status", ""), max_len=8),
                    data.get("note", ""),
                )
                entries.append((url, values, self._row_tags(data.get("status", ""), row_index)))
                row_index += 1
        elif view == "IPs":
            items = []
            for key, data in self.ips.items():
                ip, related = key
                if not self._passes_ip_filter(ip, related, data, query, status_f):
                    continue
                items.append((key, data))
            if sort["col"]:
                items.sort(key=lambda it: self._sort_key(view, sort["col"], it), reverse=sort["reverse"])
            else:
                items.sort(key=lambda it: it[0][0].lower())
            for key, data in items:
                ip, related = key
                iid = f"{ip}|{related}"
                values = (
                    ip,
                    self._format_probe_details(data),
                    related,
                    data.get("note", ""),
                )
                entries.append((iid, values, self._row_tags("", row_index)))
                row_index += 1
        elif view == "Buckets":
            items = [
                (url, data) for url, data in self.buckets.items()
                if self._passes_bucket_filter(url, data, query, status_f)
            ]
            if sort["col"]:
                items.sort(key=lambda it: self._sort_key(view, sort["col"], it), reverse=sort["reverse"])
            else:
                items.sort(key=lambda it: it[0].lower())
            for url, data in items:
                values = (
                    url,
                    self._short_status_label(data.get("status", ""), max_len=8),
                    self._short_tool_label(data.get("tools", ""), max_len=12),
                    data.get("note", ""),
                )
                entries.append((url, values, self._row_tags(data.get("status", ""), row_index)))
                row_index += 1
        elif view == "Sensitive":
            items = [
                (url, data) for url, data in self.sensitive.items()
                if self._passes_sensitive_filter(url, data, query, status_f)
            ]
            if sort["col"]:
                items.sort(key=lambda it: self._sort_key(view, sort["col"], it), reverse=sort["reverse"])
            else:
                items.sort(key=lambda it: it[0].lower())
            for url, data in items:
                values = (
                    url,
                    self._short_tool_label(data.get("tools", ""), max_len=12),
                    self._short_status_label(data.get("status", ""), max_len=8),
                    data.get("note", ""),
                )
                entries.append((url, values, self._row_tags(data.get("status", ""), row_index)))
                row_index += 1
        elif view == "JS":
            items = [
                (url, data) for url, data in self.js_files.items()
                if self._passes_js_filter(url, data, query, status_f)
            ]
            if sort["col"]:
                items.sort(key=lambda it: self._sort_key(view, sort["col"], it), reverse=sort["reverse"])
            else:
                items.sort(key=lambda it: it[0].lower())
            for url, data in items:
                values = (
                    url,
                    self._short_tool_label(data.get("tools", ""), max_len=12),
                    self._short_status_label(data.get("status", ""), max_len=8),
                    data.get("note", ""),
                )
                entries.append((url, values, self._row_tags(data.get("status", ""), row_index)))
                row_index += 1

        if hasattr(tree, "sync_rows"):
            tree.sync_rows(entries)
        else:
            for item in tree.get_children():
                tree.delete(item)
            row_index = 0
            for iid, values, tags in entries:
                tree.insert("", "end", iid=iid, values=values, tags=tags)
                row_index += 1

        if hasattr(self, "search_result_label"):
            if self._is_filter_active():
                filtered = self._filtered_counts()
                total_all = sum(filtered.values())
                new_text = f"{len(items)} shown · {total_all} total"
            else:
                new_text = ""
            if new_text != self._search_result_cache:
                self._search_result_cache = new_text
                self.search_result_label.configure(text=new_text)

        self._update_stats_display()

    def _app_alive(self):
        try:
            return bool(self.winfo_exists())
        except TclError:
            return False

    def _safe_messagebox(self, fn, *args, **kwargs):
        if not self._app_alive():
            return None
        try:
            return fn(*args, **kwargs)
        except TclError:
            return None

    def ui(self, callback, *args):
        if not self._app_alive():
            return

        def _run():
            if not self._app_alive():
                return
            try:
                callback(*args)
            except TclError:
                pass

        self.after(0, _run)

    def _schedule_persist_findings(self):
        job = getattr(self, "_persist_job", None)
        if job:
            self.after_cancel(job)
        self._persist_job = self.after(600, self._persist_session_findings)

    def _persist_session_findings(self):
        self._persist_job = None
        if not self.current_session_dir:
            return
        try:
            save_session_findings(self.current_session_dir, {
                **self._build_scan_meta(),
                "results": list(self.results),
            })
        except OSError as exc:
            self.log(f"[WORKSPACE] Could not save findings.json: {exc}")

    def log(self, msg):
        self.logs.insert("end", msg + "\n")
        self.logs.see("end")

    def update_status(self, text):
        self.status_label.configure(text=f"Status: {text}")

    def _collect_tool_report(self):
        counts = defaultdict(lambda: {"subdomains": 0, "urls": 0, "ips": 0, "buckets": 0, "discoveries": 0})

        for tool, total in self.tool_counts.items():
            if total:
                counts[tool]["discoveries"] = total

        for _host, data in self.hosts.items():
            tool = self._host_display_tool(data)
            if tool:
                counts[tool]["subdomains"] += 1

        for _url, data in self.urls.items():
            tool = self._primary_tool(data.get("tools", ""))
            if tool:
                counts[tool]["urls"] += 1

        for (_ip, _related), data in self.ips.items():
            tool = self._primary_tool(data.get("tools", ""))
            if tool:
                counts[tool]["ips"] += 1

        for _url, data in self.buckets.items():
            tool = self._primary_tool(data.get("tools", ""))
            if tool:
                counts[tool]["buckets"] += 1

        for _url, data in self.sensitive.items():
            tool = self._primary_tool(data.get("tools", ""))
            if tool:
                counts[tool]["sensitive"] = counts[tool].get("sensitive", 0) + 1

        for _url, data in self.js_files.items():
            tool = self._primary_tool(data.get("tools", ""))
            if tool:
                counts[tool]["js"] = counts[tool].get("js", 0) + 1

        rows = []
        for tool, data in counts.items():
            total = data.get("discoveries") or (
                data["subdomains"] + data["urls"] + data["ips"] + data["buckets"]
            )
            rows.append((tool, data["subdomains"], data["urls"], data["ips"], data["buckets"], total))
        rows.sort(key=lambda row: (-row[5], row[0].lower()))
        return rows

    def _tool_report_totals(self, rows):
        return (
            sum(r[1] for r in rows),
            sum(r[2] for r in rows),
            sum(r[3] for r in rows),
            sum(r[4] for r in rows),
            sum(r[5] for r in rows),
        )

    def _format_tool_report_text(self, rows):
        stats = self._collect_stats()
        sub, urls, ips, buckets, total = self._tool_report_totals(rows)
        lines = [
            "Tool Discovery Report",
            f"Target: {self.current_target or 'N/A'}",
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            f"Totals — Subdomains: {stats['subdomains']} | URLs: {stats['urls']} | "
            f"IPs: {stats['ips']} | Buckets: {stats['buckets']}",
            "",
            f"{'Tool':<24} {'Subdomains':>10} {'URLs':>8} {'IPs':>8} {'Buckets':>8} {'Total':>8}",
            "-" * 72,
        ]
        for tool, s, u, i, b, t in rows:
            lines.append(f"{tool:<24} {s:>10} {u:>8} {i:>8} {b:>8} {t:>8}")
        lines.extend([
            "-" * 72,
            f"{'TOTAL (unique finds)':<24} {sub:>10} {urls:>8} {ips:>8} {buckets:>8} {total:>8}",
        ])
        return "\n".join(lines)

    def open_tool_report(self):
        rows = self._collect_tool_report()
        stats = self._collect_stats()

        win = ctk.CTkToplevel(self)
        win.title("Tool Discovery Report")
        win.geometry("780x520")
        win.minsize(640, 400)
        win.transient(self)

        header = ctk.CTkFrame(win, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(14, 6))
        ctk.CTkLabel(header, text="Tool Discovery Report", font=FONT_DIALOG_TITLE).pack(anchor="w")
        target_text = self.current_target or "No target selected"
        ctk.CTkLabel(
            header,
            text=f"Target: {target_text}  ·  Profile: {self.profile_var.get()}",
            font=FONT_SM, text_color="#888888",
        ).pack(anchor="w", pady=(2, 0))

        summary = ctk.CTkFrame(win)
        summary.pack(fill="x", padx=16, pady=(0, 8))
        for label, key, color in (
            ("Subdomains", "subdomains", "#4fc3f7"),
            ("URLs", "urls", "#ffb74d"),
            ("IPs", "ips", "#ce93d8"),
            ("Buckets", "buckets", "#ff8a65"),
        ):
            card = ctk.CTkFrame(summary, corner_radius=8)
            card.pack(side="left", fill="x", expand=True, padx=4, pady=4)
            ctk.CTkLabel(card, text=label, font=FONT_STATS_LABEL, text_color="#999999").pack(
                anchor="w", padx=10, pady=(6, 0),
            )
            ctk.CTkLabel(card, text=str(stats[key]), font=FONT_STATS_NUM, text_color=color).pack(
                anchor="w", padx=10, pady=(0, 6),
            )

        table_frame = ctk.CTkFrame(win)
        table_frame.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        cols = ("tool", "subdomains", "urls", "ips", "buckets", "total")
        headings = {
            "tool": "Tool", "subdomains": "Subdomains", "urls": "URLs",
            "ips": "IPs", "buckets": "Buckets", "total": "Total",
        }
        tree = ttk.Treeview(table_frame, columns=cols, show="headings", style="Recon.Treeview")
        for col in cols:
            tree.heading(col, text=headings[col])
            w = 220 if col == "tool" else 90
            tree.column(col, width=w, anchor="w" if col == "tool" else "center")
        tree.grid(row=0, column=0, sticky="nsew")
        row_tags_for_tree(tree)
        tree.tag_configure("total", font=("Arial", 14, "bold"))

        if not rows:
            tree.insert("", "end", values=("No findings yet", "—", "—", "—", "—", "—"))
        else:
            for tool, s, u, i, b, t in rows:
                tree.insert("", "end", values=(tool, s, u, i, b, t), tags=("mono",))
            sub, urls, ips, buckets, total = self._tool_report_totals(rows)
            tree.insert("", "end", values=("TOTAL", sub, urls, ips, buckets, total), tags=("total",))

        ctk.CTkLabel(
            win,
            text="Counts show total discoveries per tool (includes duplicates).",
            font=FONT_XS, text_color="#888888",
        ).pack(anchor="w", padx=16, pady=(0, 4))

        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 14))

        def save_report():
            if not rows:
                messagebox.showinfo("Tool Report", "No findings to export.", parent=win)
                return
            path = filedialog.asksaveasfilename(
                parent=win, defaultextension=".txt", title="Save Tool Report",
                filetypes=[("Text", "*.txt"), ("All", "*.*")],
            )
            if path:
                Path(path).write_text(self._format_tool_report_text(rows), encoding="utf-8")
                self.log(f"[REPORT] Tool report saved -> {path}")
                messagebox.showinfo("Tool Report", f"Saved to {path}", parent=win)

        def copy_report():
            if not rows:
                return
            self.clipboard_clear()
            self.clipboard_append(self._format_tool_report_text(rows))
            messagebox.showinfo("Tool Report", "Report copied to clipboard.", parent=win)

        ctk.CTkButton(btn_row, text="Copy", width=90, height=36, font=self.ui_font, command=copy_report).pack(side="right", padx=4)
        ctk.CTkButton(btn_row, text="Save TXT", width=100, height=36, font=self.ui_font, command=save_report).pack(side="right", padx=4)
        ctk.CTkButton(btn_row, text="Close", width=90, height=36, fg_color="#444444", font=self.ui_font, command=win.destroy).pack(side="right", padx=4)

        win.update_idletasks()
        win.lift()
        win.focus_force()

    def apply_profile(self, profile):
        self.selected_tools = set(SCAN_PROFILES.get(profile, TOOL_NAMES))
        self.profile_var.set(profile)
        if hasattr(self, "profile_label"):
            self.profile_label.configure(text=f"Profile: {profile}")
        for tool in TOOL_NAMES:
            self.set_tool(tool, self.tools.get(tool, "Pending"))

    def open_tool_picker(self):
        win = ctk.CTkToplevel(self)
        win.title("Select Tools")
        win.geometry("460x560")
        scroll = ctk.CTkScrollableFrame(
            win, label_text="Tools to run", label_font=self.ui_font, **CTK_SCROLLBAR_KWARGS,
        )
        scroll.pack(fill="both", expand=True, padx=10, pady=10)

        vars_map = {}
        for tool in TOOL_NAMES:
            var = ctk.BooleanVar(value=tool in self.selected_tools)
            vars_map[tool] = var
            ctk.CTkCheckBox(scroll, text=tool, variable=var, font=self.ui_font).pack(anchor="w", padx=8, pady=3)

        def save():
            self.selected_tools = {t for t, v in vars_map.items() if v.get()}
            if not self.selected_tools:
                messagebox.showwarning("Tools", "Select at least one tool.")
                return
            win.destroy()

        ctk.CTkButton(win, text="Apply", command=save, font=self.ui_font, height=36).pack(pady=8)

    def open_settings(self):
        cfg = load_config()
        win = ctk.CTkToplevel(self)
        win.title("Settings")
        win.geometry("560x920")
        scroll = ctk.CTkScrollableFrame(win, **CTK_SCROLLBAR_KWARGS)
        scroll.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(scroll, text="Scan profile", font=FONT_SECTION).pack(anchor="w", pady=(4, 4))
        profile_var = ctk.StringVar(value=self.profile_var.get())
        profile_menu = ctk.CTkOptionMenu(
            scroll,
            values=list(SCAN_PROFILES.keys()),
            variable=profile_var,
            command=lambda p: self.apply_profile(p),
            font=self.ui_font, height=34,
        )
        profile_menu.pack(fill="x", pady=(0, 8))

        ctk.CTkButton(
            scroll, text="Customize tools...", command=self.open_tool_picker,
            font=self.ui_font, height=34,
        ).pack(anchor="w", pady=(0, 12))

        ctk.CTkLabel(scroll, text="Appearance", font=FONT_SECTION).pack(anchor="w", pady=(4, 4))
        theme_row = ctk.CTkFrame(scroll, fg_color="transparent")
        theme_row.pack(fill="x", pady=(0, 12))
        ctk.CTkButton(
            theme_row, text="Toggle dark / light theme", command=self.toggle_theme,
            font=self.ui_font, height=34,
        ).pack(side="left")

        ctk.CTkLabel(scroll, text="API & scope", font=FONT_SECTION).pack(anchor="w", pady=(4, 4))

        fields = {}
        for key in (
            "securitytrails_api_key", "virustotal_api_key", "github_token",
            "shodan_api_key", "amass_config", "scope_file",
        ):
            ctk.CTkLabel(scroll, text=key, anchor="w", font=self.ui_font).pack(fill="x", pady=(8, 0))
            entry = ctk.CTkEntry(scroll, font=self.ui_font, height=34)
            entry.insert(0, str(cfg.get(key, "")))
            entry.pack(fill="x")
            fields[key] = entry

        wordlist_fields = {}
        for key, label in (("dns_wordlist", "DNS wordlist (FFUF DNS)"), ("path_wordlist", "Path wordlist (FFUF Path)")):
            ctk.CTkLabel(scroll, text=label, anchor="w", font=self.ui_font).pack(fill="x", pady=(8, 0))
            row = ctk.CTkFrame(scroll, fg_color="transparent")
            row.pack(fill="x")
            entry = ctk.CTkEntry(row, font=self.ui_font, height=34)
            entry.insert(0, str(cfg.get(key, "")))
            entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
            wordlist_fields[key] = entry

            def browse(target_key=key, target_entry=entry):
                path = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All", "*.*")])
                if path:
                    target_entry.delete(0, "end")
                    target_entry.insert(0, path)

            ctk.CTkButton(row, text="Browse", width=80, height=34, font=self.ui_font, command=browse).pack(side="right")

        ctk.CTkLabel(scroll, text="Nuclei templates folder (JS Recon)", font=self.ui_font).pack(fill="x", pady=(8, 0))
        nuclei_row = ctk.CTkFrame(scroll, fg_color="transparent")
        nuclei_row.pack(fill="x")
        nuclei_entry = ctk.CTkEntry(nuclei_row, font=self.ui_font, height=34)
        nuclei_entry.insert(0, str(cfg.get("nuclei_templates", "")))
        nuclei_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))

        def browse_nuclei():
            path = filedialog.askdirectory(initialdir=nuclei_entry.get() or str(Path.home()))
            if path:
                nuclei_entry.delete(0, "end")
                nuclei_entry.insert(0, path)

        ctk.CTkButton(nuclei_row, text="Browse", width=80, height=34, font=self.ui_font, command=browse_nuclei).pack(side="right")

        ctk.CTkLabel(scroll, text="Scan output folder", font=self.ui_font).pack(fill="x", pady=(8, 0))
        workspace_row = ctk.CTkFrame(scroll, fg_color="transparent")
        workspace_row.pack(fill="x")
        workspace_entry = ctk.CTkEntry(workspace_row, font=self.ui_font, height=34)
        workspace_entry.insert(0, str(cfg.get("scan_workspace") or self.scan_workspace or ""))
        workspace_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))

        def browse_workspace():
            path = filedialog.askdirectory(initialdir=workspace_entry.get() or str(Path.home()))
            if path:
                workspace_entry.delete(0, "end")
                workspace_entry.insert(0, path)

        ctk.CTkButton(workspace_row, text="Browse", width=80, height=34, font=self.ui_font, command=browse_workspace).pack(side="right")

        ctk.CTkLabel(scroll, text="scope_domains (comma separated)", font=self.ui_font).pack(fill="x", pady=(8, 0))
        scope_entry = ctk.CTkEntry(scroll, font=self.ui_font, height=34)
        scope_entry.insert(0, ", ".join(cfg.get("scope_domains", [])))
        scope_entry.pack(fill="x")

        notify_var = ctk.BooleanVar(value=cfg.get("notify_on_complete", True))
        dedupe_var = ctk.BooleanVar(value=cfg.get("url_dedupe", True))
        param_var = ctk.BooleanVar(value=cfg.get("url_param_filter", True))
        ctk.CTkCheckBox(scroll, text="Notify on scan complete", variable=notify_var, font=self.ui_font).pack(anchor="w", pady=4)
        ctk.CTkCheckBox(scroll, text="URL dedupe", variable=dedupe_var, font=self.ui_font).pack(anchor="w", pady=2)
        ctk.CTkCheckBox(scroll, text="URL param filter", variable=param_var, font=self.ui_font).pack(anchor="w", pady=2)

        ctk.CTkLabel(scroll, text="My wordlist → GitHub", font=FONT_SECTION).pack(anchor="w", pady=(12, 4))
        github_wordlist_fields = {}
        for key, label in (
            ("github_wordlist_repo", "GitHub repo (owner/repo)"),
            ("github_wordlist_path", "File path in repo"),
            ("github_wordlist_branch", "Branch"),
            ("github_wordlist_commit_message", "Commit message"),
        ):
            ctk.CTkLabel(scroll, text=label, anchor="w", font=self.ui_font).pack(fill="x", pady=(8, 0))
            entry = ctk.CTkEntry(scroll, font=self.ui_font, height=34)
            entry.insert(0, str(cfg.get(key, "")))
            entry.pack(fill="x")
            github_wordlist_fields[key] = entry

        auto_push_var = ctk.BooleanVar(value=cfg.get("auto_push_wordlist", True))
        ctk.CTkCheckBox(
            scroll,
            text="Auto-push my-own-wordlist.txt to GitHub on every save (uses github_token above)",
            variable=auto_push_var,
            font=self.ui_font,
        ).pack(anchor="w", pady=4)

        ctk.CTkLabel(
            scroll,
            text=f"Local files: {MY_WORDLIST.name} + {COMMON_WORDLIST.name} in wordlists/",
            wraplength=500, justify="left", font=FONT_SM, text_color="#888888",
        ).pack(anchor="w", pady=(0, 4))

        ctk.CTkLabel(
            scroll,
            text="Shortcuts: Ctrl+F search | Ctrl+N add manually | Ctrl+Enter scan | Ctrl+S save | Esc stop | Ctrl+D theme | Ctrl+1-6 tabs",
            wraplength=500, justify="left", font=FONT_SM,
        ).pack(anchor="w", pady=10)

        def save_settings():
            cfg.update({k: e.get().strip() for k, e in fields.items()})
            cfg.update({k: e.get().strip() for k, e in wordlist_fields.items()})
            cfg["scope_domains"] = [s.strip() for s in scope_entry.get().split(",") if s.strip()]
            cfg["scan_workspace"] = workspace_entry.get().strip()
            cfg["notify_on_complete"] = notify_var.get()
            cfg["url_dedupe"] = dedupe_var.get()
            cfg["url_param_filter"] = param_var.get()
            cfg["nuclei_templates"] = nuclei_entry.get().strip()
            cfg["default_scan_profile"] = profile_var.get()
            cfg.update({k: e.get().strip() for k, e in github_wordlist_fields.items()})
            cfg["auto_push_wordlist"] = auto_push_var.get()
            self.apply_profile(profile_var.get())
            self.scan_workspace = resolve_workspace(workspace_entry.get().strip())
            cfg["scan_workspace"] = self.scan_workspace
            self._update_workspace_label()
            save_config(cfg)
            messagebox.showinfo("Settings", "Settings saved to config.json")
            win.destroy()

        ctk.CTkButton(win, text="Save", command=save_settings, font=self.ui_font, height=36).pack(pady=8)

    def import_hosts_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if not path:
            return
        lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        self.import_hosts = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
        self.log(f"[IMPORT] Loaded {len(self.import_hosts)} hosts from {path}")

    def get_targets(self):
        targets = []
        primary = self.target_entry.get().strip()
        if primary:
            targets.append(primary)
        for line in self.queue_box.get("1.0", "end").splitlines():
            line = line.strip()
            if line:
                targets.append(line)
        seen = set()
        ordered = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                ordered.append(t)
        return ordered

    def _normalize_scan_target(self, value):
        value = str(value or "").strip().lower()
        for prefix in ("http://", "https://"):
            if value.startswith(prefix):
                value = value[len(prefix):]
        return value.split("/")[0].split(":")[0].strip()

    def _selected_pipeline_tools(self):
        active = self.selected_tools if self.selected_tools else set(TOOL_NAMES)
        return [t for t in TOOL_NAMES if t in active]

    def _has_partial_progress(self):
        pipeline = self._selected_pipeline_tools()
        if not pipeline:
            return False
        completed = set(self.completed_tools or [])
        if not completed:
            return False
        return any(tool not in completed for tool in pipeline)

    def _same_scan_target(self, targets):
        if not targets:
            return False
        primary = self._normalize_scan_target(targets[0])
        saved = self._normalize_scan_target(
            (self.resume_state or {}).get("target") or self.current_target or ""
        )
        return bool(primary and saved and primary == saved)

    def _should_auto_resume(self, targets):
        if not self._same_scan_target(targets):
            return False
        if can_resume(self.resume_state):
            return True
        return self._has_partial_progress() and bool(self.hosts or self.urls or self.results)

    def _prepare_auto_resume(self, targets):
        if not can_resume(self.resume_state):
            self.resume_state = self._capture_resume_state()
        if self.resume_state and targets:
            self.resume_state["target"] = self._normalize_scan_target(targets[0])

    def _has_saveable_scan(self):
        return bool(self.results or self.hosts or self.current_session_dir)

    def _archive_current_scan(self):
        job = getattr(self, "_persist_job", None)
        if job:
            self.after_cancel(job)
            self._persist_job = None

        if not self._has_saveable_scan():
            return None

        target = self.current_target or self.target_entry.get().strip()
        session_dir = self.current_session_dir
        self.scan_workspace = resolve_workspace(self.scan_workspace)

        if not session_dir and target and self.scan_workspace:
            try:
                session_dir = create_scan_session(self.scan_workspace, target)
            except OSError as exc:
                self.log(f"[WORKSPACE] Could not archive scan: {exc}")
                return None

        if not session_dir:
            return None

        try:
            completed_at = datetime.now(timezone.utc).isoformat()
            meta = self._build_scan_meta()
            meta["scan_status"] = "complete"
            meta["scan_completed_at"] = completed_at
            meta["completed_at"] = completed_at
            meta["resume_from_tool"] = ""
            save_session_findings(session_dir, {**meta, "results": list(self.results)})
            existing = read_session_meta(session_dir)
            save_session_meta(session_dir, {
                **existing,
                "target": target or existing.get("target", ""),
                "profile": self.profile_var.get(),
                "scan_status": "complete",
                "completed_at": completed_at,
                "subdomains": len(self.hosts),
                "urls": len(self.urls),
                "live_hosts": sum(
                    1 for data in self.hosts.values()
                    if str(data.get("status", "")).strip() not in ("", "-")
                ),
            })
            return str(session_dir)
        except OSError as exc:
            self.log(f"[WORKSPACE] Archive failed: {exc}")
            return None

    def _begin_fresh_scan(self, targets):
        self.scanning = True
        self.stop_requested = False
        self._resume_mode = False
        self.resume_state = None
        self.completed_tools = []
        self.loaded_scan_label = ""
        self.last_scan_time = ""
        self.current_session_dir = None
        self._update_scan_time_label()
        self.start_btn.configure(state="disabled")
        self.new_scan_btn.configure(state="disabled")
        self.resume_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.reset_scan_ui()
        self._update_resume_btn()
        threading.Thread(target=self.run_scan_queue, args=(targets,), kwargs={"resume": False}, daemon=True).start()

    def reset_scan_ui(self):
        self.hosts.clear()
        self.urls.clear()
        self.ips.clear()
        self.buckets.clear()
        self.sensitive.clear()
        self.js_files.clear()
        self.results.clear()
        self.completed_tools = []
        self.loaded_scan_label = ""
        self.logs.delete("1.0", "end")
        for tool in TOOL_NAMES:
            self.set_tool(tool, "Pending")
            self.tool_counts[tool] = 0
        self._refresh_tool_summary()
        self.progress.set(0)
        self.progress_label.configure(text="Starting...")
        self._on_data_changed()

    def set_tool(self, tool, status):
        style = TOOL_STATUS_STYLE.get(status, TOOL_STATUS_STYLE["Pending"])
        row_data = self.tool_rows.get(tool)
        if row_data:
            selected = tool in self.selected_tools if self.selected_tools else True
            text_color = style["text"] if selected else "#5a6270"
            row_data["row"].configure(fg_color=style["bg"])
            row_data["accent"].configure(fg_color=style["accent"])
            row_data["badge"].configure(text=style["badge"], text_color=style["badge_fg"])
            row_data["name"].configure(text_color=text_color)
            count = self.tool_counts.get(tool, 0)
            if count > 0:
                row_data["count"].configure(text=str(count), text_color="#7ec8e3")
            elif status in ("Done", "Skipped", "Error"):
                row_data["count"].configure(text="0", text_color="#555")
            else:
                row_data["count"].configure(text="")
        self.tools[tool] = status
        self._refresh_tool_summary()

    def bump_tool_count(self, tool):
        if tool not in self.tool_counts:
            return
        self.tool_counts[tool] += 1
        row_data = self.tool_rows.get(tool)
        if row_data:
            row_data["count"].configure(text=str(self.tool_counts[tool]), text_color="#7ec8e3")

    def on_tool_start(self, tool):
        self.active_tool.configure(text=f"Active: {tool}")
        self.set_tool(tool, "Running")
        self.skip_btn.configure(state="normal")
        group = self.tool_rows.get(tool, {}).get("group")
        if group and group in self.tool_group_bodies:
            body = self.tool_group_bodies[group]
            if not body.winfo_ismapped():
                header = self.tool_group_headers[group]
                header.invoke()
        self.after(80, lambda t=tool: self._scroll_tool_into_view(t))

    def on_tool_done(self, tool, status):
        self.set_tool(tool, status)
        self.skip_btn.configure(state="disabled")
        if status in ("Done", "Skipped", "Error") and tool not in self.completed_tools:
            self.completed_tools.append(tool)
        self._schedule_persist_findings()

    def _sync_ui_from_resume_state(self):
        state = (self.resume_state or {}).get("runner_state") or {}
        subdomains = state.get("subdomains") or {}
        host_ips = state.get("host_ips") or {}
        live = set(state.get("live_hosts") or [])
        for host, sources in subdomains.items():
            if host in self.hosts:
                continue
            src_list = sources if isinstance(sources, list) else [sources]
            tool = src_list[0] if src_list else "Import"
            status = "200" if host in live else "-"
            ip = host_ips.get(host, "-")
            self.hosts[host] = {
                "sources": [tool], "status": status, "ip": ip,
                "screenshot": "", "note": "",
            }
            self._append_result({
                "type": "host", "value": host, "tools": tool,
                "status": status, "ip": ip, "screenshot": "", "note": "",
            })
        if subdomains:
            self._on_data_changed(refresh_view=True)

    def _capture_resume_state(self, scan_completed_at=""):
        runner_state = None
        if self.runner:
            runner_state = self.runner.export_state()
        return capture_resume_state(
            profile=self.profile_var.get(),
            selected_tools=self.selected_tools,
            tool_statuses=self.tools,
            completed_tools=self.completed_tools,
            hosts=self.hosts,
            urls=self.urls,
            sensitive=self.sensitive,
            js_files=self.js_files,
            domain=self.current_target,
            runner_state=runner_state,
            session_dir=self.current_session_dir or "",
            scan_completed_at=scan_completed_at or self.last_scan_time,
            tool_counts=self.tool_counts,
        )

    def _update_resume_btn(self):
        if hasattr(self, "resume_btn"):
            state = "normal" if can_resume(self.resume_state) and not self.scanning else "disabled"
            self.resume_btn.configure(state=state)

    def _apply_resume_tool_statuses(self):
        if not self.resume_state:
            return
        statuses = self.resume_state.get("tool_statuses") or {}
        completed = set(self.resume_state.get("completed_tools") or [])
        self.completed_tools = list(self.resume_state.get("completed_tools") or [])
        for tool in TOOL_NAMES:
            if tool in completed:
                self.set_tool(tool, statuses.get(tool, "Done"))
            elif tool in statuses:
                saved = statuses[tool]
                self.set_tool(tool, "Pending" if saved == "Running" else saved)
            else:
                self.set_tool(tool, "Pending")
        resume_tool = self.resume_state.get("resume_from_tool", "")
        if resume_tool:
            self.progress_label.configure(text=f"Resuming from {resume_tool}...")
        saved_counts = self.resume_state.get("tool_counts") or {}
        for tool, count in saved_counts.items():
            if tool not in self.tool_counts:
                continue
            self.tool_counts[tool] = int(count)
            row_data = self.tool_rows.get(tool)
            if row_data and count:
                row_data["count"].configure(text=str(count), text_color="#7ec8e3")
        self._refresh_tool_summary()

    def on_scan_progress(self, current, total, tool):
        self.progress.set(current / total if total else 0)
        elapsed = time.time() - self.scan_start_time
        eta = int((elapsed / current) * (total - current)) if current else 0
        self.progress_label.configure(text=f"Tool {current}/{total}: {tool} | Elapsed {int(elapsed)}s | ETA ~{eta}s")
        self.active_tool.configure(text=f"Active: {tool}")

    def on_scan_blocked(self, domain):
        self.log(f"[ERROR] {domain} is outside scope — add it to scope.txt or Settings")
        self.progress_label.configure(text="Blocked (out of scope)")
        self.update_status("Scan blocked")

    def _primary_tool(self, tools):
        if isinstance(tools, list):
            return tools[0] if tools else ""
        text = str(tools or "").strip()
        if not text:
            return ""
        return text.split(",")[0].strip()

    def _host_display_tool(self, data):
        return self._primary_tool(data.get("sources", []))

    def _append_result(self, row):
        for i, existing in enumerate(self.results):
            if existing.get("type") == row.get("type") and existing.get("value") == row.get("value"):
                merged = {**existing, **row}
                if existing.get("tools"):
                    merged["tools"] = existing["tools"]
                self.results[i] = merged
                return
        self.results.append(row)

    def _empty_host(self, tool="", status="-", ip="-"):
        return {
            "sources": [tool] if tool else [],
            "status": status,
            "ip": ip,
            "content_length": "",
            "title": "",
            "tech": "",
            "content_type": "",
            "screenshot": "",
            "note": "",
        }

    def _apply_probe_fields(self, data, probe):
        if not probe:
            return
        for key in ("status", "ip", "content_length", "title", "tech", "content_type"):
            val = probe.get(key)
            if val is not None and str(val).strip() not in ("", "-"):
                data[key] = str(val)

    def add_or_update_host(self, host, tool, status="-", ip="-", count_finding=False):
        if host not in self.hosts:
            self.hosts[host] = self._empty_host(tool, status, ip)
        else:
            data = self.hosts[host]
            if tool and tool not in data["sources"]:
                data["sources"].append(tool)
            if status != "-":
                data["status"] = status
            if ip != "-":
                data["ip"] = ip
        if count_finding and tool:
            self.bump_tool_count(tool)
        data = self.hosts[host]
        self._append_result({
            "type": "host", "value": host,
            "tools": self._host_display_tool(data),
            "status": data["status"], "ip": data["ip"],
            "content_length": data.get("content_length", ""),
            "title": data.get("title", ""),
            "tech": data.get("tech", ""),
            "screenshot": data.get("screenshot", ""), "note": data.get("note", ""),
        })
        self._on_data_changed(refresh_view=True)
        self._schedule_persist_findings()

    def update_host_probe(self, host, probe, tool="HTTP Probe", count_finding=False):
        if isinstance(probe, str):
            probe = {"status": probe, "ip": tool if tool and tool != "HTTP Probe" else "-"}
            tool = "HTTP Probe"
        if host not in self.hosts:
            self.hosts[host] = self._empty_host(tool)
        data = self.hosts[host]
        if tool and tool not in data["sources"]:
            data["sources"].append(tool)
        self._apply_probe_fields(data, probe)
        if count_finding and tool:
            self.bump_tool_count(tool)
        self._append_result({
            "type": "host", "value": host,
            "tools": self._host_display_tool(data),
            "status": data["status"], "ip": data["ip"],
            "content_length": data.get("content_length", ""),
            "title": data.get("title", ""),
            "tech": data.get("tech", ""),
            "screenshot": data.get("screenshot", ""), "note": data.get("note", ""),
        })
        self._on_data_changed(refresh_view=True)
        self._schedule_persist_findings()

    def update_ip_probe(self, ip, related, probe):
        key = (ip, related)
        if key not in self.ips:
            self.ips[key] = {"tools": "HTTP Probe", "note": "", "status": "-", "content_length": "", "title": "", "tech": ""}
        data = self.ips[key]
        if "HTTP Probe" not in str(data.get("tools", "")):
            existing = str(data.get("tools", "")).strip()
            data["tools"] = "HTTP Probe" if not existing else f"{existing}, HTTP Probe"
        self._apply_probe_fields(data, probe)
        if related in self.hosts and self.hosts[related]["ip"] == "-":
            self.hosts[related]["ip"] = ip
        self._append_result({
            "type": "ip", "value": ip, "tools": data["tools"], "related": related,
            "status": data.get("status", "-"),
            "content_length": data.get("content_length", ""),
            "title": data.get("title", ""),
            "tech": data.get("tech", ""),
            "note": data.get("note", ""),
        })
        self.bump_tool_count("HTTP Probe")
        self._on_data_changed(refresh_view=True)
        self._schedule_persist_findings()

    def set_host_screenshot(self, host, path):
        if host in self.hosts:
            self.hosts[host]["screenshot"] = path
            self.add_or_update_host(host, self.hosts[host]["sources"][0])

    def add_url_result(self, tool, url, status="-", count_finding=False):
        if is_js_url(url):
            self.add_js_result(tool, url, status, count_finding=count_finding)
            return
        if url not in self.urls:
            self.urls[url] = {"tools": tool, "status": status, "note": ""}
        elif status != "-":
            self.urls[url]["status"] = status
        if count_finding and tool:
            self.bump_tool_count(tool)
        self._append_result({
            "type": "url", "value": url,
            "tools": self.urls[url]["tools"],
            "status": self.urls[url]["status"],
            "note": self.urls[url].get("note", ""),
        })
        self._on_data_changed(refresh_view=True)
        self._schedule_persist_findings()

    def add_ip_result(self, tool, related, ip, count_finding=False):
        key = (ip, related)
        if key not in self.ips:
            self.ips[key] = {
                "tools": tool, "note": "", "status": "-",
                "content_length": "", "title": "", "tech": "",
            }
        if count_finding and tool:
            self.bump_tool_count(tool)
        if related in self.hosts and self.hosts[related]["ip"] == "-":
            self.hosts[related]["ip"] = ip
        self._append_result({"type": "ip", "value": ip, "tools": tool, "related": related, "note": ""})
        self._on_data_changed(refresh_view=True)
        self._schedule_persist_findings()

    def add_bucket_result(self, tool, url, status="-", count_finding=False):
        if url not in self.buckets:
            self.buckets[url] = {"tools": tool, "status": status, "note": ""}
        elif status != "-":
            self.buckets[url]["status"] = status
        if count_finding and tool:
            self.bump_tool_count(tool)
        self._append_result({
            "type": "bucket", "value": url,
            "tools": self.buckets[url]["tools"],
            "status": self.buckets[url]["status"],
            "note": self.buckets[url].get("note", ""),
        })
        self._on_data_changed(refresh_view=True)
        self._schedule_persist_findings()

    def add_sensitive_result(self, tool, url, status="-", note="", count_finding=False):
        if url not in self.sensitive:
            self.sensitive[url] = {"tools": tool, "status": status, "note": note}
        else:
            if status != "-":
                self.sensitive[url]["status"] = status
            if note and not self.sensitive[url].get("note"):
                self.sensitive[url]["note"] = note
        if count_finding and tool:
            self.bump_tool_count(tool)
        self._append_result({
            "type": "sensitive", "value": url,
            "tools": self.sensitive[url]["tools"],
            "status": self.sensitive[url]["status"],
            "note": self.sensitive[url].get("note", ""),
        })
        self._on_data_changed(refresh_view=True)
        self._schedule_persist_findings()

    def add_js_result(self, tool, url, status="-", note="", count_finding=False):
        if url in self.urls:
            self.urls.pop(url, None)
            self._remove_result_row("url", url)
        if url not in self.js_files:
            self.js_files[url] = {"tools": tool, "status": status, "note": note}
        else:
            if status != "-":
                self.js_files[url]["status"] = status
            if note:
                self.js_files[url]["note"] = note
        if count_finding and tool:
            self.bump_tool_count(tool)
        self._append_result({
            "type": "js", "value": url,
            "tools": self.js_files[url]["tools"],
            "status": self.js_files[url]["status"],
            "note": self.js_files[url].get("note", ""),
        })
        self._on_data_changed(refresh_view=True)
        self._schedule_persist_findings()

    def add_js_results_batch(self, tool, entries, count_findings=True):
        if not entries:
            return 0
        added = 0
        for url, status, note in entries:
            if not url:
                continue
            if url in self.urls:
                self.urls.pop(url, None)
                self._remove_result_row("url", url)
            if url not in self.js_files:
                self.js_files[url] = {"tools": tool, "status": status, "note": note}
                added += 1
            else:
                if status != "-":
                    self.js_files[url]["status"] = status
                if note:
                    self.js_files[url]["note"] = note
            self._append_result({
                "type": "js", "value": url,
                "tools": self.js_files[url]["tools"],
                "status": self.js_files[url]["status"],
                "note": self.js_files[url].get("note", ""),
            })
            if count_findings and tool:
                self.bump_tool_count(tool)
        self._on_data_changed(refresh_view=True)
        self._schedule_persist_findings()
        return added

    def _normalize_subdomain(self, value):
        host = value.strip().lower()
        if host.startswith("http://") or host.startswith("https://"):
            host = host.split("://", 1)[1].split("/")[0].split(":")[0]
        if host.startswith("*."):
            host = host[2:]
        return host

    def manual_add_subdomain(self, value, status="-", ip="-"):
        host = self._normalize_subdomain(value)
        if not host or " " in host or "/" in host:
            return "invalid", host
        if host in self.hosts:
            return "exists", host
        self.hosts[host] = {
            "sources": [self.MANUAL_TOOL], "status": status, "ip": ip,
            "screenshot": "", "note": "",
        }
        self._append_result({
            "type": "host", "value": host,
            "tools": self.MANUAL_TOOL, "status": status, "ip": ip,
            "screenshot": "", "note": "",
        })
        return "added", host

    def manual_add_url(self, value, status="-"):
        raw = value.strip()
        if not raw or " " in raw:
            return "invalid", raw
        url = normalize_url(raw)
        if not url:
            return "invalid", raw
        if is_js_url(url):
            return self.manual_add_js(url, status=status)
        if url in self.urls:
            return "exists", url
        self.urls[url] = {"tools": self.MANUAL_TOOL, "status": status, "note": ""}
        self._append_result({
            "type": "url", "value": url, "tools": self.MANUAL_TOOL,
            "status": status, "note": "",
        })
        return "added", url

    def manual_add_ip(self, value, related=""):
        ip = value.strip()
        if not ip or " " in ip:
            return "invalid", ip
        related = related.strip() or self.current_target or "-"
        if any(existing_ip == ip for existing_ip, _ in self.ips):
            return "exists", ip
        key = (ip, related)
        self.ips[key] = {"tools": self.MANUAL_TOOL, "note": ""}
        if related in self.hosts and self.hosts[related]["ip"] == "-":
            self.hosts[related]["ip"] = ip
        self._append_result({
            "type": "ip", "value": ip, "tools": self.MANUAL_TOOL,
            "related": related, "note": "",
        })
        return "added", ip

    def manual_add_bucket(self, value, status="-"):
        url = value.strip()
        if not url or " " in url:
            return "invalid", url
        if url in self.buckets:
            return "exists", url
        self.buckets[url] = {"tools": self.MANUAL_TOOL, "status": status, "note": ""}
        self._append_result({
            "type": "bucket", "value": url, "tools": self.MANUAL_TOOL,
            "status": status, "note": "",
        })
        return "added", url

    def manual_add_sensitive(self, value, status="-", note=""):
        url = value.strip()
        if not url or " " in url:
            return "invalid", url
        if not url.startswith("http"):
            url = normalize_url(url) or url
        if url in self.sensitive:
            return "exists", url
        self.sensitive[url] = {"tools": self.MANUAL_TOOL, "status": status, "note": note}
        self._append_result({
            "type": "sensitive", "value": url, "tools": self.MANUAL_TOOL,
            "status": status, "note": note,
        })
        return "added", url

    def manual_add_js(self, value, status="-", note=""):
        url = value.strip()
        if not url or " " in url:
            return "invalid", url
        if not url.startswith("http"):
            url = normalize_url(url) or url
        if url in self.js_files:
            return "exists", url
        self.js_files[url] = {"tools": self.MANUAL_TOOL, "status": status, "note": note}
        self._append_result({
            "type": "js", "value": url, "tools": self.MANUAL_TOOL,
            "status": status, "note": note,
        })
        return "added", url

    def _manual_add_line(self, kind, line):
        line = line.strip()
        if not line or line.startswith("#"):
            return "skip", line

        if kind == "Subdomains":
            return self.manual_add_subdomain(line)
        if kind == "URLs":
            return self.manual_add_url(line)
        if kind == "IPs":
            if "," in line:
                ip_part, related_part = line.split(",", 1)
                return self.manual_add_ip(ip_part, related_part)
            return self.manual_add_ip(line)
        if kind == "Buckets":
            return self.manual_add_bucket(line)
        if kind == "Sensitive":
            if "\t" in line:
                url, note = line.split("\t", 1)
                return self.manual_add_sensitive(url, note=note.strip())
            return self.manual_add_sensitive(line)
        if kind == "JS":
            if "\t" in line:
                url, note = line.split("\t", 1)
                return self.manual_add_js(url, note=note.strip(), status="secret" if note.strip() else "js")
            return self.manual_add_js(line)
        return "invalid", line

    def open_manual_add_dialog(self):
        if getattr(self, "_manual_add_win", None):
            try:
                if self._manual_add_win.winfo_exists():
                    self._manual_add_win.lift()
                    self._manual_add_win.focus_force()
                    return
            except Exception:
                pass

        win = ctk.CTkToplevel(self)
        self._manual_add_win = win
        win.title("Add findings manually")
        win.geometry("520x480")
        win.minsize(420, 400)
        win.transient(self)

        def close_dialog():
            self._manual_add_win = None
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", close_dialog)
        win.bind("<Escape>", lambda _e: close_dialog())

        body = ctk.CTkFrame(win)
        body.pack(fill="both", expand=True, padx=16, pady=14)
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(
            body, text="Add findings manually", font=FONT_DIALOG_TITLE,
        ).grid(row=0, column=0, sticky="w", pady=(0, 8))

        type_row = ctk.CTkFrame(body, fg_color="transparent")
        type_row.grid(row=1, column=0, sticky="ew", pady=(0, 4))
        ctk.CTkLabel(type_row, text="Type", font=self.ui_font).pack(side="left", padx=(0, 8))
        type_var = ctk.StringVar(value=self._current_view)
        type_menu = ctk.CTkOptionMenu(
            type_row, values=list(self.VIEWS), variable=type_var, width=180,
            font=self.ui_font, height=34,
        )
        type_menu.pack(side="left")

        hints = {
            "Subdomains": "One subdomain per line, e.g. api.example.com",
            "URLs": "One URL per line (http/https added if missing)",
            "IPs": "One IP per line, or ip,hostname for related host",
            "Buckets": "One bucket URL per line, e.g. s3://bucket-name",
            "Sensitive": "Sensitive URL per line, optional note after tab",
            "JS": "JS file URL per line, optional secret snippet after tab",
        }
        hint_label = ctk.CTkLabel(body, text=hints[self._current_view], font=FONT_SM, text_color="#888888")
        hint_label.grid(row=2, column=0, sticky="w", pady=(0, 6))

        def on_type_change(_choice):
            hint_label.configure(text=hints.get(type_var.get(), ""))

        type_menu.configure(command=on_type_change)

        ctk.CTkLabel(body, text="Entries (one per line)", anchor="w", font=self.ui_font).grid(row=3, column=0, sticky="w", pady=(0, 4))
        box = ctk.CTkTextbox(body, height=240, font=self.ui_font)
        box.grid(row=4, column=0, sticky="nsew", pady=(0, 10))

        btn_row = ctk.CTkFrame(body, fg_color="transparent")
        btn_row.grid(row=5, column=0, sticky="e")

        def focus_textbox():
            win.lift()
            win.focus_force()
            box.focus_set()
            if hasattr(box, "_textbox"):
                box._textbox.focus_set()

        def submit():
            kind = type_var.get()
            lines = box.get("1.0", "end").splitlines()
            added = exists = invalid = 0
            added_items = []
            for line in lines:
                result, item = self._manual_add_line(kind, line)
                if result == "added":
                    added += 1
                    added_items.append(item)
                elif result == "exists":
                    exists += 1
                elif result == "invalid":
                    invalid += 1
            if not added and not exists and not invalid:
                messagebox.showwarning("Add manually", "Enter at least one value.", parent=win)
                focus_textbox()
                return
            if added:
                self._on_data_changed(refresh_view=True)
                for item in added_items[:5]:
                    self.log(f"[MANUAL] Added {kind}: {item}")
                if len(added_items) > 5:
                    self.log(f"[MANUAL] ... and {len(added_items) - 5} more")
            summary = f"Added: {added}"
            if exists:
                summary += f"\nAlready present (skipped): {exists}"
            if invalid:
                summary += f"\nInvalid (skipped): {invalid}"
            messagebox.showinfo("Add manually", summary, parent=win)
            if added:
                close_dialog()
            else:
                focus_textbox()

        ctk.CTkButton(btn_row, text="Cancel", width=100, height=36, fg_color="#444444", font=self.ui_font, command=close_dialog).pack(side="right", padx=4)
        ctk.CTkButton(btn_row, text="Add", width=100, height=36, font=self.ui_font, command=submit).pack(side="right", padx=4)

        win.update_idletasks()
        win.after(50, focus_textbox)

    def add_takeover_finding(self, host, cname, note):
        if host not in self.hosts:
            self.hosts[host] = {
                "sources": ["Takeover Check"], "status": "TAKEOVER?", "ip": "-",
                "screenshot": "", "note": note,
            }
        else:
            data = self.hosts[host]
            data["status"] = "TAKEOVER?"
            data["note"] = note
            if "Takeover Check" not in data["sources"]:
                data["sources"].append("Takeover Check")
        self.bump_tool_count("Takeover Check")
        data = self.hosts[host]
        self._append_result({
            "type": "host", "value": host,
            "tools": self._host_display_tool(data),
            "status": data["status"], "ip": data.get("ip", "-"),
            "screenshot": data.get("screenshot", ""), "note": note,
        })
        self._on_data_changed(refresh_view=True)
        self._schedule_persist_findings()

    def start_scan_thread(self):
        if self.scanning:
            return
        targets = self.get_targets()
        if not targets:
            self.log("[ERROR] Enter at least one target")
            return
        if not self.selected_tools:
            self.log("[ERROR] No tools selected — open Settings and pick a scan profile or tools")
            return
        self.scan_workspace = resolve_workspace(self.scan_workspace)

        if self._should_auto_resume(targets):
            self._prepare_auto_resume(targets)
            resume_tool = (self.resume_state or {}).get("resume_from_tool", "next tool")
            done = len((self.resume_state or {}).get("completed_tools") or [])
            self.log(
                f"[RESUME] Same target ({targets[0]}) — keeping previous results, "
                f"continuing from {resume_tool} ({done} tools already done)"
            )
            self.start_resume_scan_thread()
            return

        self.log(f"[+] Starting fresh scan — {len(self.selected_tools)} tools, folder: {self.scan_workspace}")
        self._begin_fresh_scan(targets)

    def start_new_scan_thread(self):
        if self.scanning:
            messagebox.showinfo("New Scan", "A scan is already running. Stop it first.")
            return
        targets = self.get_targets()
        if not targets:
            self.log("[ERROR] Enter at least one target")
            return
        if not self.selected_tools:
            self.log("[ERROR] No tools selected — open Settings and pick a scan profile or tools")
            return

        if self._has_saveable_scan():
            summary = (
                f"Target: {self.current_target or targets[0]}\n"
                f"Findings: {len(self.results)} rows · {len(self.hosts)} subdomains\n\n"
                "Save this scan to the workspace folder and start a new empty scan?"
            )
            if not messagebox.askyesno("New Scan", summary):
                return
            archived = self._archive_current_scan()
            if archived:
                self.log(f"[NEW SCAN] Previous scan saved -> {archived}")
            else:
                self.log("[NEW SCAN] Could not archive previous scan — starting fresh anyway")

        self.log(f"[+] New scan — {len(self.selected_tools)} tools, folder: {self.scan_workspace}")
        self._begin_fresh_scan(targets)

    def start_resume_scan_thread(self):
        if self.scanning:
            return
        if not can_resume(self.resume_state):
            messagebox.showinfo(
                "Resume scan",
                "No resumable scan loaded.\n\nImport a saved session or export that was saved mid-scan.",
            )
            return
        targets = self.get_targets()
        if not targets:
            self.log("[ERROR] Enter at least one target")
            return
        if not self.current_target and self.resume_state:
            self.current_target = self.resume_state.get("target") or targets[0]
            self.target_entry.delete(0, "end")
            self.target_entry.insert(0, self.current_target)

        self.scan_workspace = resolve_workspace(self.scan_workspace)
        self.scanning = True
        self.stop_requested = False
        self._resume_mode = True
        self.loaded_scan_label = "Resumed scan"
        self.last_scan_time = ""
        self._update_scan_time_label()
        self.start_btn.configure(state="disabled")
        self.new_scan_btn.configure(state="disabled")
        self.resume_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.logs.delete("1.0", "end")
        self._apply_resume_tool_statuses()
        self._sync_ui_from_resume_state()
        resume_tool = self.resume_state.get("resume_from_tool", "?")
        self.log(
            f"[RESUME] Continuing from {resume_tool} — "
            f"{len(self.completed_tools)} tools already done, folder: {self.scan_workspace}"
        )
        threading.Thread(target=self.run_scan_queue, args=(targets,), kwargs={"resume": True}, daemon=True).start()

    def stop_scan(self):
        self.stop_requested = True
        if self.runner:
            self.runner.request_stop()
        self.resume_state = self._capture_resume_state()
        self._update_resume_btn()
        self.log("[!] Stopping scan...")

    def skip_current_tool(self):
        if self.runner:
            self.runner.request_skip()
            self.log("[!] Skipping current tool...")

    def rerun_tool(self, tool):
        if tool not in TOOL_NAMES:
            return
        if self.scanning:
            messagebox.showinfo("Rerun tool", "A scan is already running. Stop or wait for it to finish first.")
            return

        domain = self._normalize_scan_target(self.current_target or self.target_entry.get())
        if not domain:
            messagebox.showwarning("Rerun tool", "Enter a target domain first.")
            return

        self.scanning = True
        self.stop_requested = False
        self.runner = None

        self.start_btn.configure(state="disabled")
        self.new_scan_btn.configure(state="disabled")
        self.resume_btn.configure(state="disabled")
        self.stop_btn.configure(state="disabled")
        self.skip_btn.configure(state="disabled")

        runner_state = build_runner_state_from_ui(
            self.hosts, self.urls, self.sensitive, self.js_files, domain=domain,
        )
        session_dir = self.current_session_dir

        def worker():
            try:
                runner = ScanRunner(
                    selected_tools=TOOL_NAMES,
                    import_hosts=self.import_hosts,
                    session_dir=session_dir,
                    scan_profile=self.profile_var.get(),
                )
                runner.load_runner_state(runner_state)

                callbacks = {
                    "log": lambda msg: self.ui(self.log, msg),
                    "tool_start": lambda t: self.ui(self.on_tool_start, t),
                    "tool_done": lambda t, s: self.ui(self.on_tool_done, t, s),
                    "scan_progress": lambda _c, _tot, _t: None,
                    "scan_blocked": lambda d: self.ui(self.on_scan_blocked, d),
                    "host_found": lambda h, t, st, ip: self.ui(self.add_or_update_host, h, t, st, ip, True),
                    "host_update": lambda h, probe: self.ui(self.update_host_probe, h, probe, "HTTP Probe", True),
                    "ip_probe_update": lambda ip, rel, probe: self.ui(self.update_ip_probe, ip, rel, probe),
                    "hosts_prune": lambda hosts: self.ui(self.remove_hosts, hosts),
                    "url_found": lambda t, u, st: self.ui(self.add_url_result, t, u, st, True),
                    "ip_found": lambda t, rel, ip: self.ui(self.add_ip_result, t, rel, ip, True),
                    "bucket_found": lambda t, u, st: self.ui(self.add_bucket_result, t, u, st, True),
                    "sensitive_found": lambda t, u, st, n: self.ui(self.add_sensitive_result, t, u, st, n, True),
                    "js_found": lambda t, u, st, n: self.ui(self.add_js_result, t, u, st, n, True),
                    "js_batch_found": lambda t, entries: self.ui(self.add_js_results_batch, t, entries, True),
                    "takeover_found": lambda h, c, n: self.ui(self.add_takeover_finding, h, c, n),
                    "screenshot": lambda h, p: self.ui(self.set_host_screenshot, h, p),
                }
                runner.run_tool_once(domain, tool, callbacks)
            except Exception as exc:
                self.ui(self.log, f"[ERROR] Re-run {tool} failed: {exc}")
                self.ui(self.log, traceback.format_exc())
            finally:
                self.ui(self._rerun_tool_finished)

        threading.Thread(target=worker, daemon=True).start()

    def _rerun_tool_finished(self):
        self.scanning = False
        self.runner = None
        self.start_btn.configure(state="normal")
        self.new_scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.skip_btn.configure(state="disabled")
        self._update_resume_btn()

    def run_scan_queue(self, targets, resume=False):
        try:
            for index, domain in enumerate(targets, start=1):
                if self.stop_requested:
                    break
                self.ui(self.log, f"\n=== Target {index}/{len(targets)}: {domain} ===")
                self.ui(lambda d=domain: (setattr(self, "current_target", d), self.update_window_title()))
                self.ui(self.update_status, f"Scanning {domain} ({index}/{len(targets)})")
                self.scan_start_time = time.time()
                self.run_scan(domain, resume=resume and index == 1)
                resume = False
        except Exception as exc:
            self.ui(self.log, f"[ERROR] Scan queue failed: {exc}")
        finally:
            self.ui(self._scan_finished)

    def run_scan(self, domain, resume=False):
        session_dir = None
        try:
            self.scan_workspace = resolve_workspace(self.scan_workspace)
            if resume and self.resume_state:
                saved_session = self.resume_state.get("session_dir", "")
                if saved_session and Path(saved_session).is_dir():
                    session_dir = Path(saved_session)
                    self.current_session_dir = session_dir
                    self.ui(self.log, f"[RESUME] Reusing scan folder -> {session_dir}")
                elif self.scan_workspace:
                    try:
                        session_dir = create_scan_session(self.scan_workspace, domain)
                        self.current_session_dir = session_dir
                        self.ui(self.log, f"[WORKSPACE] Saving tool outputs -> {session_dir}")
                    except OSError as exc:
                        self.ui(self.log, f"[WORKSPACE ERROR] Cannot save to {self.scan_workspace}: {exc}")
            elif self.scan_workspace:
                try:
                    session_dir = create_scan_session(self.scan_workspace, domain)
                    self.current_session_dir = session_dir
                    self.ui(self.log, f"[WORKSPACE] Saving tool outputs -> {session_dir}")
                except OSError as exc:
                    self.ui(self.log, f"[WORKSPACE ERROR] Cannot save to {self.scan_workspace}: {exc}")
                    self.ui(self.log, "[!] Scan will continue without saving raw tool files.")
            self.runner = ScanRunner(
                selected_tools=self.selected_tools,
                import_hosts=self.import_hosts,
                session_dir=session_dir,
                scan_profile=self.profile_var.get(),
            )
            callbacks = {
                "log": lambda msg: self.ui(self.log, msg),
                "tool_start": lambda t: self.ui(self.on_tool_start, t),
                "tool_done": lambda t, s: self.ui(self.on_tool_done, t, s),
                "scan_progress": lambda c, tot, t: self.ui(self.on_scan_progress, c, tot, t),
                "scan_blocked": lambda d: self.ui(self.on_scan_blocked, d),
                "host_found": lambda h, t, st, ip: self.ui(self.add_or_update_host, h, t, st, ip, True),
                "host_update": lambda h, probe: self.ui(self.update_host_probe, h, probe, "HTTP Probe", True),
                "ip_probe_update": lambda ip, rel, probe: self.ui(self.update_ip_probe, ip, rel, probe),
                "hosts_prune": lambda hosts: self.ui(self.remove_hosts, hosts),
                "url_found": lambda t, u, st: self.ui(self.add_url_result, t, u, st, True),
                "ip_found": lambda t, rel, ip: self.ui(self.add_ip_result, t, rel, ip, True),
                "bucket_found": lambda t, u, st: self.ui(self.add_bucket_result, t, u, st, True),
                "sensitive_found": lambda t, u, st, n: self.ui(self.add_sensitive_result, t, u, st, n, True),
                "js_found": lambda t, u, st, n: self.ui(self.add_js_result, t, u, st, n, True),
                "js_batch_found": lambda t, entries: self.ui(self.add_js_results_batch, t, entries, True),
                "takeover_found": lambda h, c, n: self.ui(self.add_takeover_finding, h, c, n),
                "screenshot": lambda h, p: self.ui(self.set_host_screenshot, h, p),
            }
            resume_kwargs = {}
            if resume and self.resume_state:
                resume_kwargs = {
                    "completed_tools": self.resume_state.get("completed_tools"),
                    "runner_state": self.resume_state.get("runner_state"),
                    "tool_statuses": self.resume_state.get("tool_statuses"),
                }
            self.runner.run_full_scan(domain, callbacks, **resume_kwargs)
        except Exception as exc:
            self.ui(self.log, f"[ERROR] Scan failed: {exc}")
            self.ui(self.log, traceback.format_exc())

    def _scan_finished(self):
        self.scanning = False
        self.runner = None
        self.start_btn.configure(state="normal")
        self.new_scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.skip_btn.configure(state="disabled")
        if self.stop_requested:
            self.progress_label.configure(text="Stopped")
            self.update_status("Scan stopped")
            self.resume_state = self._capture_resume_state()
            if self.current_target:
                self.resume_state["target"] = self._normalize_scan_target(self.current_target)
            self.log(
                f"[RESUME] Scan paused — resume from "
                f"{self.resume_state.get('resume_from_tool') or 'next tool'} "
                f"(Save session to keep progress)"
            )
            self._safe_messagebox(
                messagebox.showinfo,
                "Scan stopped",
                "Progress saved in memory.\n\n"
                "Use Save session to export, or click Resume to continue.",
            )
        else:
            self.progress.set(1)
            self.progress_label.configure(text="Complete")
            self.last_scan_time = datetime.now(timezone.utc).isoformat()
            self.loaded_scan_label = "Last scan"
            self.resume_state = self._capture_resume_state(scan_completed_at=self.last_scan_time)
            self.resume_state["scan_status"] = "complete"
            self.resume_state["resume_from_tool"] = ""
            self._update_scan_time_label()
            self.update_status("Scan Completed")
            self._on_data_changed(refresh_view=True)
            self._persist_session_findings()
            if self.hosts:
                self.switch_view("Subdomains")
            self.notify_complete()
            return
        self._update_scan_time_label()
        self._on_data_changed(refresh_view=True)
        self._persist_session_findings()
        self._update_resume_btn()

    def notify_complete(self):
        if not self._app_alive():
            return
        cfg = load_config()
        if not cfg.get("notify_on_complete", True):
            return
        try:
            subprocess.run(
                ["notify-send", "Recon Engine", f"Scan completed — {self.current_target}"],
                check=False, timeout=3,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        self._safe_messagebox(
            messagebox.showinfo,
            "Scan Complete",
            f"Finished scanning {self.current_target or 'targets'}",
        )

    def _on_table_select(self, event):
        tree = self.active_tree()
        item = self._table_event_row(event)
        if item:
            tree.selection_set(item)

    def on_table_click(self, event):
        tree = self.active_tree()
        if self._table_event_region(event) != "cell":
            return
        if self._current_view != "Subdomains":
            return
        if self._table_event_column(event) != "#1":
            return
        item = self._table_event_row(event)
        if not item:
            return
        data = self.hosts.get(item)
        if data and data.get("screenshot"):
            self.open_screenshot(data["screenshot"])

    def on_double_click(self, event):
        tree = self.active_tree()
        col = self._table_event_column(event)
        item = self._table_event_row(event)
        if not item:
            return
        cols = self.tables[self._current_view]["cols"]
        col_index = int(col.replace("#", "")) - 1
        if col_index < 0 or col_index >= len(cols):
            return
        if cols[col_index] == "note":
            self.edit_note_for_item(item)
            return
        self.open_selection()

    def show_context_menu(self, event):
        tree = self.active_tree()
        item = self._table_event_row(event)
        if not item:
            return
        tree.selection_set(item)
        self._open_table_context_menu(item, event.x_root, event.y_root)

    def _remove_result_row(self, rtype, value, related=""):
        self.results = [
            row for row in self.results
            if not (
                row.get("type") == rtype
                and row.get("value") == value
                and (rtype != "ip" or row.get("related", "") == related)
            )
        ]

    def remove_hosts(self, hosts):
        if not hosts:
            return 0
        removed = 0
        for host in hosts:
            if host not in self.hosts:
                continue
            self.hosts.pop(host, None)
            self._remove_result_row("host", host)
            removed += 1
        if removed:
            self._on_data_changed(refresh_view=True)
            self._schedule_persist_findings()
        return removed

    def remove_selection(self):
        tree = self.active_tree()
        sel = tree.selection()
        if not sel:
            return
        item = sel[0]
        view = self._current_view
        label = item

        if view == "Subdomains":
            data = self.hosts.pop(item, None)
            if data is None:
                return
            label = item
            self._remove_result_row("host", item)
        elif view == "URLs":
            if item not in self.urls:
                return
            label = item
            self.urls.pop(item, None)
            self._remove_result_row("url", item)
        elif view == "IPs":
            if "|" not in item:
                return
            ip, related = item.split("|", 1)
            if (ip, related) not in self.ips:
                return
            label = ip
            self.ips.pop((ip, related), None)
            self._remove_result_row("ip", ip, related)
        elif view == "Buckets":
            if item not in self.buckets:
                return
            label = item
            self.buckets.pop(item, None)
            self._remove_result_row("bucket", item)
        elif view == "Sensitive":
            if item not in self.sensitive:
                return
            label = item
            self.sensitive.pop(item, None)
            self._remove_result_row("sensitive", item)
        elif view == "JS":
            if item not in self.js_files:
                return
            label = item
            self.js_files.pop(item, None)
            self._remove_result_row("js", item)
        else:
            return

        self.log(f"[REMOVE] {view}: {label}")
        if hasattr(tree, "delete"):
            tree.delete(item)
        self._update_stats_display()
        self._on_data_changed(refresh_view=False)
        self._schedule_persist_findings()

    def copy_selection(self):
        tree = self.active_tree()
        sel = tree.selection()
        if not sel:
            return
        vals = tree.item(sel[0])["values"]
        self.clipboard_clear()
        self.clipboard_append(str(vals[0] if self._current_view != "Subdomains" else vals[1]))

    def _selection_endpoint(self):
        tree = self.active_tree()
        sel = tree.selection()
        if not sel:
            return ""
        vals = tree.item(sel[0])["values"]
        view = self._current_view
        if view == "Subdomains":
            return str(vals[1] if len(vals) > 1 else vals[0]).strip()
        return str(vals[0]).strip()

    def _set_wordlist_status_color(self, kind="ok"):
        label = getattr(self, "_wordlist_status_label", None)
        if not label or not label.winfo_exists():
            return
        colors = {"ok": "#9cdc9c", "warn": "#e6b84d", "err": "#e07070"}
        label.configure(text_color=colors.get(kind, colors["ok"]))

    def _format_wordlist_result(self, result, cfg):
        duplicates = result.get("duplicates") or []
        if duplicates and not result["added_my"]:
            dup = duplicates[0]
            extra = f" (+{len(duplicates) - 1} more)" if len(duplicates) > 1 else ""
            return f"Duplicate — already in my-own-wordlist.txt: {dup}{extra}", "warn"
        msg_parts = [
            f"Added {result['added_my']} to my-own-wordlist.txt",
            f"{result['added_common']} to common.txt",
        ]
        if duplicates:
            msg_parts.append(f"{len(duplicates)} duplicate(s) skipped")
        if result["added_my"] and cfg.get("auto_push_wordlist") and cfg.get("github_wordlist_repo") and cfg.get("github_token"):
            msg_parts.append("GitHub push started")
        elif result["added_my"] and cfg.get("auto_push_wordlist"):
            msg_parts.append("Set github_wordlist_repo + github_token in Settings to auto-push")
        return "; ".join(msg_parts), "ok"

    def _append_to_wordlists(self, entries, context_label, notify="dialog"):
        entries = [e for e in entries if e]
        if not entries:
            msg = f"No endpoints to save ({context_label})."
            if notify == "panel":
                self._wordlist_status_var.set(msg)
                self._set_wordlist_status_color("warn")
            else:
                messagebox.showinfo("Wordlist", msg)
            return
        cfg = load_config()
        result = append_endpoints(entries, cfg)
        summary, color = self._format_wordlist_result(result, cfg)
        self.log(f"[WORDLIST] {context_label}: {summary}")
        if notify == "panel":
            self._wordlist_status_var.set(summary)
            self._set_wordlist_status_color(color)
        elif notify == "dialog":
            if color == "warn":
                messagebox.showwarning("Wordlist", summary)
            else:
                messagebox.showinfo("Wordlist", summary)

    def add_endpoint_to_wordlist(self):
        if self._wordlist_panel and self._wordlist_panel.winfo_exists():
            self._wordlist_panel.lift()
            self._wordlist_panel.focus_force()
            return
        self._open_wordlist_panel()

    def push_wordlist_to_github_now(self, notify="dialog"):
        ensure_wordlist_files()
        cfg = load_config()
        ok, message = push_my_wordlist_to_github(cfg, async_push=False)
        self.log(f"[WORDLIST] GitHub: {message}")
        if notify == "panel":
            self._wordlist_status_var.set(message)
            return
        if ok:
            messagebox.showinfo("Wordlist", message)
        else:
            messagebox.showwarning("Wordlist", message)

    def open_selection(self):
        tree = self.active_tree()
        sel = tree.selection()
        if not sel:
            return
        vals = tree.item(sel[0])["values"]
        view = self._current_view
        value = vals[0] if view != "Subdomains" else vals[1]
        url = value if str(value).startswith("http") else f"https://{value}"
        webbrowser.open(url)

    def edit_note_selection(self):
        tree = self.active_tree()
        sel = tree.selection()
        if sel:
            self.edit_note_for_item(sel[0])

    def edit_note_for_item(self, item_id):
        view = self._current_view
        existing = ""
        if view == "Subdomains" and item_id in self.hosts:
            existing = self.hosts[item_id].get("note", "")
        elif view == "URLs" and item_id in self.urls:
            existing = self.urls[item_id].get("note", "")
        elif view == "IPs" and "|" in item_id:
            ip, rel = item_id.split("|", 1)
            existing = self.ips.get((ip, rel), {}).get("note", "")
        elif view == "Buckets" and item_id in self.buckets:
            existing = self.buckets[item_id].get("note", "")
        elif view == "Sensitive" and item_id in self.sensitive:
            existing = self.sensitive[item_id].get("note", "")
        elif view == "JS" and item_id in self.js_files:
            existing = self.js_files[item_id].get("note", "")

        note = simpledialog.askstring("Note", "Enter note:", initialvalue=existing)
        if note is None:
            return
        if view == "Subdomains" and item_id in self.hosts:
            self.hosts[item_id]["note"] = note
            self.add_or_update_host(item_id, self.hosts[item_id]["sources"][0])
        elif view == "URLs" and item_id in self.urls:
            self.urls[item_id]["note"] = note
            self._append_result({"type": "url", "value": item_id, **self.urls[item_id], "tools": self.urls[item_id]["tools"]})
        elif view == "IPs":
            ip, rel = item_id.split("|", 1)
            key = (ip, rel)
            if key in self.ips:
                self.ips[key]["note"] = note
        elif view == "Buckets" and item_id in self.buckets:
            self.buckets[item_id]["note"] = note
        elif view == "Sensitive" and item_id in self.sensitive:
            self.sensitive[item_id]["note"] = note
        elif view == "JS" and item_id in self.js_files:
            self.js_files[item_id]["note"] = note
        self.refresh_current_view()

    def tag_selection(self, tag):
        tree = self.active_tree()
        sel = tree.selection()
        if not sel:
            return
        item = sel[0]
        view = self._current_view
        if view == "Subdomains" and item in self.hosts:
            self.hosts[item]["note"] = tag
            self.add_or_update_host(item, self.hosts[item]["sources"][0])
        elif view == "URLs" and item in self.urls:
            self.urls[item]["note"] = tag
        elif view == "IPs":
            ip, rel = item.split("|", 1)
            if (ip, rel) in self.ips:
                self.ips[(ip, rel)]["note"] = tag
        elif view == "Buckets" and item in self.buckets:
            self.buckets[item]["note"] = tag
        elif view == "Sensitive" and item in self.sensitive:
            self.sensitive[item]["note"] = tag
        elif view == "JS" and item in self.js_files:
            self.js_files[item]["note"] = tag
        self.refresh_current_view()

    def open_screenshot(self, path):
        if not path or not Path(path).is_file():
            messagebox.showinfo("Screenshot", "No screenshot available.")
            return
        try:
            from PIL import Image, ImageTk
            top = ctk.CTkToplevel(self)
            top.title(Path(path).name)
            top.geometry("920x640")
            img = Image.open(path)
            img.thumbnail((880, 580))
            photo = ImageTk.PhotoImage(img)
            label = ctk.CTkLabel(top, text="", image=photo)
            label.image = photo
            label.pack(padx=10, pady=10)
        except Exception:
            webbrowser.open(Path(path).as_uri())

    def _update_workspace_label(self):
        if not hasattr(self, "workspace_label"):
            return
        path = self.scan_workspace or "Not set"
        short = path if len(path) <= 42 else f"…{path[-39:]}"
        self.workspace_label.configure(text=f"Scan folder: {short}")

    def _init_scan_workspace(self):
        cfg = load_config()
        self.scan_workspace = resolve_workspace(cfg.get("scan_workspace") or self.scan_workspace)
        if cfg.get("scan_workspace") != self.scan_workspace:
            cfg["scan_workspace"] = self.scan_workspace
            save_config(cfg)
            self.log(f"[WORKSPACE] Using writable folder: {self.scan_workspace}")
        self._update_workspace_label()
        if not cfg.get("scan_workspace"):
            self.after(100, lambda: self.choose_scan_workspace(prompt_on_cancel=True))
        else:
            self.after(100, self._offer_load_latest_scan)

    def choose_scan_workspace(self, prompt_on_cancel=False):
        initial = self.scan_workspace or str(default_workspace())
        path = filedialog.askdirectory(
            title="Choose folder to save all scan outputs",
            initialdir=initial if Path(initial).is_dir() else str(Path.home()),
        )
        if not path:
            if prompt_on_cancel:
                self.scan_workspace = resolve_workspace("")
                cfg = load_config()
                cfg["scan_workspace"] = self.scan_workspace
                save_config(cfg)
                self.log(f"[WORKSPACE] Using default folder: {self.scan_workspace}")
            self._update_workspace_label()
            return
        if not is_workspace_writable(path):
            messagebox.showerror(
                "Scan folder",
                f"Cannot write to:\n{path}\n\nChoose a folder where you have write permission.",
            )
            return
        self.scan_workspace = str(Path(path).resolve())
        ensure_workspace(self.scan_workspace)
        cfg = load_config()
        cfg["scan_workspace"] = self.scan_workspace
        save_config(cfg)
        self._update_workspace_label()
        self.log(f"[WORKSPACE] Scan outputs -> {self.scan_workspace}")
        self._offer_load_latest_scan()

    def _offer_load_latest_scan(self):
        session = latest_session(self.scan_workspace)
        if not session:
            return
        meta = {}
        meta_path = session / "meta.json"
        if meta_path.is_file():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        target = meta.get("target", session.parent.name)
        when = format_scan_time(meta.get("completed_at") or meta.get("started_at", ""))
        if messagebox.askyesno(
            "Load saved scan",
            f"Found a saved scan for {target}\n({when})\n\nLoad it into the dashboard?",
        ):
            self.load_scan_session_dir(session)

    def _scan_ingest(self, kind, value, tool, status="-", extra=""):
        if kind == "host_probe":
            self.update_host_probe(value, extra if isinstance(extra, dict) else {"status": status}, tool, count_finding=False)
        elif kind == "ip_probe":
            related = self.current_target or (extra.get("related") if isinstance(extra, dict) else "") or value
            self.update_ip_probe(value, related, extra if isinstance(extra, dict) else {"status": status})
        elif kind == "host":
            self.add_or_update_host(value, tool, status, extra or "-")
        elif kind == "url":
            self.add_url_result(tool, value, status)
        elif kind == "ip":
            self.add_ip_result(tool, extra or self.current_target, value)
        elif kind == "bucket":
            self.add_bucket_result(tool, value, status)
        elif kind == "sensitive":
            self.add_sensitive_result(tool, value, status, extra)
        elif kind == "js":
            self.add_js_result(tool, value, status, extra)
        elif kind == "js_batch":
            self.add_js_results_batch(tool, value, count_findings=False)
        elif kind == "takeover":
            self.add_takeover_finding(value, tool, extra)
        elif kind == "screenshot":
            self.set_host_screenshot(value, extra)

    def load_scan_session_dir(self, session_dir):
        self.reset_scan_ui()
        self.current_session_dir = Path(session_dir)
        meta = load_session_from_disk(session_dir, self._scan_ingest)
        self.current_target = meta.get("target", session_dir.parent.name if session_dir.parent else "")
        if meta.get("profile"):
            self.apply_profile(meta["profile"])
        self.last_scan_time = meta.get("completed_at") or meta.get("started_at") or meta.get("saved_at") or meta.get("scan_completed_at", "")
        self.loaded_scan_label = "Loaded scan"
        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, self.current_target)
        self._on_data_changed(refresh_view=True)
        if self.hosts:
            self.switch_view("Subdomains")
        self.update_window_title()
        self._update_scan_time_label()
        self.update_status(f"Loaded · {len(self.hosts)} subdomains, {len(self.results)} findings")
        loaded_from = "findings.json" if (Path(session_dir) / "findings.json").is_file() else "tool files"
        self.log(f"[WORKSPACE] Loaded scan from {session_dir} ({loaded_from})")

    def load_latest_workspace_scan(self):
        if not self.scan_workspace:
            messagebox.showinfo("Scan folder", "Choose a scan folder first.")
            return
        session = latest_session(self.scan_workspace)
        if not session:
            messagebox.showinfo("Scan folder", "No saved scans found in the workspace folder.")
            return
        self.load_scan_session_dir(session)

    def _build_scan_meta(self):
        resume = self._capture_resume_state(scan_completed_at=self.last_scan_time)
        if self.last_scan_time and not self.stop_requested:
            resume["scan_status"] = "complete"
            resume["resume_from_tool"] = ""
        return {
            "target": self.current_target,
            "targets": self.get_targets(),
            "profile": self.profile_var.get(),
            "scan_completed_at": self.last_scan_time,
            **resume,
        }

    def _update_scan_time_label(self):
        if not hasattr(self, "scan_time_label"):
            return
        if self.last_scan_time:
            label = "Last scan" if not self.loaded_scan_label else self.loaded_scan_label
            self.scan_time_label.configure(text=f"{label}: {format_scan_time(self.last_scan_time)}")
        else:
            self.scan_time_label.configure(text="")

    def _apply_scan_data(self, data, source_name=""):
        self.reset_scan_ui()
        self.current_target = data.get("target", "")
        self.last_scan_time = data.get("scan_completed_at") or data.get("saved_at") or data.get("exported_at") or ""
        self.loaded_scan_label = "Loaded scan" if source_name else "Last scan"

        if data.get("profile"):
            self.apply_profile(data["profile"])

        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, self.current_target)

        targets = data.get("targets") or []
        self.queue_box.delete("1.0", "end")
        queue_lines = [t for t in targets if t and t != self.current_target]
        if queue_lines:
            self.queue_box.insert("1.0", "\n".join(queue_lines))

        for row in data.get("results", []):
            t = row.get("type")
            if t == "host":
                first_tool = self._primary_tool(row.get("tools", ""))
                self.hosts[row["value"]] = {
                    "sources": [first_tool] if first_tool else [],
                    "status": row.get("status", "-"), "ip": row.get("ip", "-"),
                    "content_length": row.get("content_length", ""),
                    "title": row.get("title", ""),
                    "tech": row.get("tech", ""),
                    "content_type": row.get("content_type", ""),
                    "screenshot": row.get("screenshot", ""), "note": row.get("note", ""),
                }
            elif t == "url":
                if is_js_url(row["value"]):
                    self.js_files[row["value"]] = {
                        "tools": self._primary_tool(row.get("tools", "")),
                        "status": row.get("status", "-"), "note": row.get("note", ""),
                    }
                    row = {**row, "type": "js"}
                else:
                    self.urls[row["value"]] = {
                        "tools": self._primary_tool(row.get("tools", "")),
                        "status": row.get("status", "-"), "note": row.get("note", ""),
                    }
            elif t == "ip":
                self.ips[(row["value"], row.get("related", ""))] = {
                    "tools": self._primary_tool(row.get("tools", "")),
                    "status": row.get("status", "-"),
                    "content_length": row.get("content_length", ""),
                    "title": row.get("title", ""),
                    "tech": row.get("tech", ""),
                    "note": row.get("note", ""),
                }
            elif t == "bucket":
                self.buckets[row["value"]] = {
                    "tools": self._primary_tool(row.get("tools", "")),
                    "status": row.get("status", "-"), "note": row.get("note", ""),
                }
            elif t == "sensitive":
                self.sensitive[row["value"]] = {
                    "tools": self._primary_tool(row.get("tools", "")),
                    "status": row.get("status", "-"), "note": row.get("note", ""),
                }
            elif t == "js":
                self.js_files[row["value"]] = {
                    "tools": self._primary_tool(row.get("tools", "")),
                    "status": row.get("status", "-"), "note": row.get("note", ""),
                }
            row = {**row, "tools": self._primary_tool(row.get("tools", ""))}
            self.results.append(row)

        self.resume_state = extract_resume_fields(data, self.selected_tools)
        if not self.resume_state.get("runner_state"):
            self.resume_state["runner_state"] = build_runner_state_from_ui(
                self.hosts, self.urls, self.sensitive, self.js_files, self.current_target,
            )
        self.completed_tools = list(self.resume_state.get("completed_tools") or [])
        self._apply_resume_tool_statuses()
        self._update_resume_btn()
        self._on_data_changed()
        self.update_window_title()
        self._update_scan_time_label()
        self.update_status(f"Loaded · {len(self.results)} findings")
        return len(self.results)

    def _offer_resume_scan(self):
        if not can_resume(self.resume_state):
            return
        resume_tool = self.resume_state.get("resume_from_tool", "")
        completed = len(self.resume_state.get("completed_tools") or [])
        if messagebox.askyesno(
            "Resume scan",
            f"This scan was not finished.\n\n"
            f"Completed tools: {completed}\n"
            f"Resume from: {resume_tool}\n\n"
            f"Continue the scan now?",
        ):
            self.start_resume_scan_thread()

    def import_scan_export_file(self):
        path = filedialog.askopenfilename(
            title="Import scan export",
            filetypes=[
                ("Recon exports", "*.json *.txt *.xlsx *.html"),
                ("JSON", "*.json"),
                ("Text", "*.txt"),
                ("Excel", "*.xlsx"),
                ("HTML", "*.html"),
                ("All", "*.*"),
            ],
        )
        if not path:
            return
        try:
            data = import_scan_file(path)
            count = self._apply_scan_data(data, source_name=Path(path).name)
            self.log(
                f"[IMPORT] Restored scan from {Path(path).name} — "
                f"{count} findings · {format_scan_time(self.last_scan_time)}"
            )
            resume_tool = (self.resume_state or {}).get("resume_from_tool", "")
            msg = (
                f"Loaded scan from:\n{Path(path).name}\n\n"
                f"Target: {self.current_target or 'N/A'}\n"
                f"Scan time: {format_scan_time(self.last_scan_time)}\n"
                f"Findings: {count}"
            )
            if can_resume(self.resume_state):
                msg += f"\n\nResume from: {resume_tool}"
            messagebox.showinfo("Import scan", msg)
            self._offer_resume_scan()
        except Exception as exc:
            messagebox.showerror("Import scan", f"Could not import file:\n{exc}")
            self.log(f"[IMPORT ERROR] {exc}")

    def _export_path(self, ext, title):
        return filedialog.asksaveasfilename(defaultextension=ext, title=title)

    def save_as_txt(self):
        if not self.results:
            messagebox.showinfo("Export", "No results to export.")
            return
        path = self._export_path(".txt", "Save TXT")
        if path:
            export_txt(path, self.results, self._build_scan_meta())
            self.log(f"[SAVE] TXT -> {path} (re-import via File → Import scan export)")

    def save_as_excel(self):
        if not self.results:
            messagebox.showinfo("Export", "No results to export.")
            return
        path = self._export_path(".xlsx", "Save Excel")
        if path:
            export_excel(path, self.results, self._build_scan_meta())
            self.log(f"[SAVE] Excel -> {path} (re-import via File → Import scan export)")

    def save_as_html(self):
        if not self.results:
            messagebox.showinfo("Export", "No results to export.")
            return
        path = self._export_path(".html", "Save HTML Report")
        if path:
            meta = self._build_scan_meta()
            meta["generated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            payload = build_scan_payload(
                target=meta["target"],
                results=self.results,
                profile=meta["profile"],
                scan_completed_at=meta["scan_completed_at"],
                targets=meta["targets"],
            )
            export_html(path, self.results, self.current_target, meta, import_payload=payload)
            self.log(f"[SAVE] HTML -> {path} (re-import via File → Import scan export)")

    def save_session_file(self):
        path = self._export_path(".json", "Save Session")
        if not path:
            return
        meta = self._build_scan_meta()
        save_session(path, {
            "target": meta["target"],
            "targets": meta["targets"],
            "profile": meta["profile"],
            "scan_completed_at": meta["scan_completed_at"],
            "results": self.results,
            "scan_status": meta.get("scan_status", ""),
            "completed_tools": meta.get("completed_tools", []),
            "resume_from_tool": meta.get("resume_from_tool", ""),
            "tool_statuses": meta.get("tool_statuses", {}),
            "runner_state": meta.get("runner_state", {}),
            "session_dir": meta.get("session_dir", ""),
        })
        self.log(f"[SESSION] Saved -> {path}")
        if can_resume(self.resume_state):
            self.log(f"[SESSION] Resume point: {self.resume_state.get('resume_from_tool')}")

    def load_session_file(self):
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if not path:
            return
        try:
            data = import_scan_file(path)
            count = self._apply_scan_data(data, source_name=Path(path).name)
            self.log(f"[SESSION] Loaded {count} rows from {path}")
            self._offer_resume_scan()
        except Exception as exc:
            messagebox.showerror("Load session", f"Could not load session:\n{exc}")

    def diff_session_files(self):
        old_path = filedialog.askopenfilename(title="Old session", filetypes=[("JSON", "*.json")])
        if not old_path:
            return
        new_path = filedialog.askopenfilename(title="New session", filetypes=[("JSON", "*.json")])
        if not new_path:
            return
        diff = diff_sessions(load_session(old_path), load_session(new_path))
        lines = []
        for key, label in (
            ("new_hosts", "New subdomains"), ("removed_hosts", "Removed subdomains"),
            ("new_urls", "New URLs"), ("removed_urls", "Removed URLs"),
            ("new_ips", "New IPs"), ("removed_ips", "Removed IPs"),
            ("new_buckets", "New buckets"), ("removed_buckets", "Removed buckets"),
        ):
            items = diff[key]
            lines.append(f"{label} ({len(items)}):")
            lines.extend(f"  + {x}" for x in items[:50])
            if len(items) > 50:
                lines.append(f"  ... and {len(items) - 50} more")
            lines.append("")
        win = ctk.CTkToplevel(self)
        win.title("Session Diff")
        win.geometry("640x540")
        box = ctk.CTkTextbox(win, font=self.ui_font)
        box.pack(fill="both", expand=True, padx=10, pady=10)
        box.insert("1.0", "\n".join(lines))


if __name__ == "__main__":
    app = ReconDashboard()
    app.mainloop()
