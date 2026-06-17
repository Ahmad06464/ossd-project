from pathlib import Path
from tkinter import Toplevel, ttk

import customtkinter as ctk

# Shared UI font sizes (Arial for labels/widgets, Consolas for table values)
FONT_XS = ("Arial", 12)
FONT_SM = ("Arial", 13)
FONT_MD = ("Arial", 15)
FONT_LG = ("Arial", 17)
FONT_XL = ("Arial", 20)
FONT_APP_TITLE = ("Arial", 20, "bold")
FONT_BRAND = ("Arial", 28, "bold")
FONT_SECTION = ("Arial", 17, "bold")
FONT_DIALOG_TITLE = ("Arial", 19, "bold")
FONT_STATS_LABEL = ("Arial", 14)
FONT_STATS_NUM = ("Arial", 28, "bold")
MONO_FONT = ("Consolas", 14)
UI_FONT = ("Arial", 14)
TABLE_HEADING = ("Arial", 14, "bold")
TOOLTIP_FONT = ("Arial", 12)

TOOL_STATUS_STYLE = {
    "Pending": {"bg": "#2b2f38", "accent": "#4a5060", "text": "#9aa3b2", "badge": "···", "badge_fg": "#666"},
    "Running": {"bg": "#1a3a5c", "accent": "#ffb74d", "text": "#ffffff", "badge": "▶", "badge_fg": "#ffb74d"},
    "Done": {"bg": "#1a3328", "accent": "#3ddc84", "text": "#c8f0d8", "badge": "✓", "badge_fg": "#3ddc84"},
    "Skipped": {"bg": "#2a2a2a", "accent": "#777", "text": "#888", "badge": "—", "badge_fg": "#777"},
    "Error": {"bg": "#3d1f1f", "accent": "#ff5252", "text": "#ffcdd2", "badge": "!", "badge_fg": "#ff5252"},
}

TOOL_GROUPS = [
    ("Discovery", (
        "Subfinder", "Assetfinder", "Findomain", "Amass Passive", "Amass Active",
        "crt.sh", "Wayback CDX", "SecurityTrails", "VirusTotal Subs", "GitHub Subs",
        "GitHub Secrets", "FFUF DNS",
    )),
    ("Probe", (
        "HTTP Probe", "Takeover Check", "FFUF Path", "Cloud Buckets", "Aquatone",
    )),
    ("Intel & URLs", (
        "VT IP Harvest", "OTX IP Harvest", "URLScan IP", "Shodan",
        "GAU", "Katana", "URLFinder", "Hakrawler", "URL Param Filter",
    )),
    ("Deep Recon", (
        "Sensitive Files", "Arjun Params", "JS Recon",
    )),
]

CTK_SCROLLBAR_KWARGS = {
    "scrollbar_fg_color": "#1a1d23",
    "scrollbar_button_color": "#3d4654",
    "scrollbar_button_hover_color": "#4fc3f7",
}


def shorten_tool_name(name, max_len=20):
    text = str(name or "").strip()
    if len(text) <= max_len:
        return text
    return f"{text[: max_len - 1]}…"


class ToolTip:
    def __init__(self, widget, text, delay=400):
        self.widget = widget
        self.text = text
        self.delay = delay
        self._tip = None
        self._after = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event=None):
        self._cancel()
        self._after = self.widget.after(self.delay, self._show)

    def _cancel(self):
        if self._after:
            self.widget.after_cancel(self._after)
            self._after = None

    def _show(self):
        if self._tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 12
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self._tip = tw = Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = ttk.Label(
            tw, text=self.text, padding=(8, 4),
            relief="solid", borderwidth=1, font=TOOLTIP_FONT,
        )
        label.pack()

    def _hide(self, _event=None):
        self._cancel()
        if self._tip:
            self._tip.destroy()
            self._tip = None


def configure_tree_style(style=None):
    style = style or ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass

    style.configure(
        "Recon.Treeview",
        background="#2a2d34",
        foreground="#e8e8e8",
        fieldbackground="#2a2d34",
        rowheight=34,
        font=UI_FONT,
        borderwidth=0,
    )
    style.configure(
        "Recon.Treeview.Heading",
        background="#1f2329",
        foreground="#cfd8dc",
        font=TABLE_HEADING,
        relief="flat",
    )
    style.map(
        "Recon.Treeview",
        background=[("selected", "#1f538d")],
        foreground=[("selected", "#ffffff")],
    )
    configure_scrollbar_style(style)
    return style


def configure_scrollbar_style(style=None):
    style = style or ttk.Style()
    for orient, name in (("vertical", "Recon.Vertical.TScrollbar"), ("horizontal", "Recon.Horizontal.TScrollbar")):
        style.configure(
            name,
            troughcolor="#1a1d23",
            background="#3d4654",
            darkcolor="#2a3039",
            lightcolor="#525d6e",
            bordercolor="#1a1d23",
            arrowcolor="#b0bec5",
            relief="flat",
            gripcount=0,
            width=11 if orient == "vertical" else 11,
        )
        style.map(
            name,
            background=[
                ("disabled", "#2a3039"),
                ("active", "#4fc3f7"),
                ("pressed", "#1f538d"),
            ],
            arrowcolor=[
                ("disabled", "#555"),
                ("active", "#ffffff"),
                ("pressed", "#ffffff"),
            ],
        )
    return style


def row_tags_for_tree(tree):
    tree.tag_configure("ok", foreground="#3ddc84")
    tree.tag_configure("warn", foreground="#ffb74d")
    tree.tag_configure("bad", foreground="#ff6b6b")
    tree.tag_configure("muted", foreground="#888888")
    tree.tag_configure("takeover", foreground="#ff5252", background="#3a1f1f")
    tree.tag_configure("zebra", background="#32363f")
    tree.tag_configure("mono", font=MONO_FONT)


def status_row_tag(status):
    s = str(status or "").upper()
    if "TAKEOVER" in s:
        return "takeover"
    if s in ("200", "204"):
        return "ok"
    if s in ("301", "302", "403"):
        return "warn"
    if s.isdigit() and int(s) >= 500:
        return "bad"
    if s in ("-", "", "PARAM"):
        return "muted"
    return ""


def _tag_colors(tags):
    bg = "#32363f" if "zebra" in tags else "#2a2d34"
    fg = "#e8e8e8"
    if "takeover" in tags:
        return "#3a1f1f", "#ff5252"
    if "ok" in tags:
        fg = "#3ddc84"
    elif "warn" in tags:
        fg = "#ffb74d"
    elif "bad" in tags:
        fg = "#ff6b6b"
    elif "muted" in tags:
        fg = "#888888"
    return bg, fg


class WrapDataTable:
    """Scrollable table with wrapping text cells and variable row heights."""

    def __init__(
        self,
        parent,
        columns,
        headings,
        col_width_fn,
        col_stretch_fn,
        col_wrap_fn,
        ui_font,
        ui_font_sm,
    ):
        self.columns = columns
        self.headings = headings
        self._col_width_fn = col_width_fn
        self._col_stretch_fn = col_stretch_fn
        self._col_wrap_fn = col_wrap_fn
        self.ui_font = ui_font
        self.ui_font_sm = ui_font_sm
        self.selected_iid = None
        self.row_data = {}
        self.row_widgets = {}
        self.header_cells = {}
        self._header_commands = {}
        self._ordered_iids = []
        self._batch = False

        self.container = ctk.CTkFrame(parent, fg_color="transparent")
        self.container.grid_rowconfigure(1, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.header = ctk.CTkFrame(self.container, fg_color="#1f2329", corner_radius=0, height=36)
        self.header.grid(row=0, column=0, sticky="ew", padx=(0, 2))
        self._configure_header_grid()
        self._build_header()

        self.scroll = ctk.CTkScrollableFrame(
            self.container, fg_color="transparent", **CTK_SCROLLBAR_KWARGS,
        )
        self.scroll.grid(row=1, column=0, sticky="nsew")
        self.scroll.grid_columnconfigure(0, weight=1)
        self._event_bindings = {}
        self.container.bind("<Configure>", self._update_wraplengths, add="+")

    def _configure_header_grid(self):
        for idx, col in enumerate(self.columns):
            stretch = self._col_stretch_fn(col)
            self.header.grid_columnconfigure(idx, weight=1 if stretch else 0, minsize=self._col_width_fn(col))

    def _build_header(self):
        for idx, col in enumerate(self.columns):
            anchor = "center" if col in ("tools", "status", "shot") else "w"
            btn = ctk.CTkButton(
                self.header,
                text=self.headings.get(col, col),
                font=TABLE_HEADING,
                height=32,
                fg_color="transparent",
                hover_color="#2f3540",
                anchor=anchor,
                command=lambda c=col: self._header_commands.get(c, lambda: None)(),
            )
            btn.grid(row=0, column=idx, sticky="nsew", padx=1, pady=2)
            self.header_cells[col] = btn

    def _wraplength_for(self, col):
        width = max(self.container.winfo_width() - 28, 200)
        fixed = 0
        for c in self.columns:
            if self._col_stretch_fn(c):
                continue
            fixed += self._col_width_fn(c)
        if self._col_stretch_fn(col):
            return max(120, width - fixed - 16)
        return max(60, self._col_width_fn(col) - 16)

    def _cell_anchor(self, col):
        if col in ("tools", "status", "shot"):
            return "center"
        if col == "probe":
            return "nw"
        return "w"

    def _cell_sticky(self, col):
        if col in ("tools", "status", "shot"):
            return "ns"
        return "nsew"

    def _update_wraplengths(self, _event=None):
        if not self.container.winfo_exists():
            return
        for data in self.row_widgets.values():
            for col, lbl in data["labels"].items():
                if self._col_wrap_fn(col):
                    text = str(lbl.cget("text") or "")
                    if col in ("note", "related") and not text.strip():
                        lbl.configure(wraplength=0)
                    else:
                        lbl.configure(wraplength=self._wraplength_for(col))

    def _bind_recursive(self, widget, sequence, func):
        widget.bind(sequence, func)
        for child in widget.winfo_children():
            self._bind_recursive(child, sequence, func)

    def _wire_row_events(self, row):
        for sequence, func in self._event_bindings.items():
            self._bind_recursive(row, sequence, func)

    def grid(self, **kwargs):
        self.container.grid(**kwargs)

    def grid_remove(self):
        self.container.grid_remove()

    def bind(self, sequence, func, add=None):
        self._event_bindings[sequence] = func
        for w in (self.container, self.scroll, self.scroll._parent_canvas):
            w.bind(sequence, func)
        for data in self.row_widgets.values():
            self._wire_row_events(data["frame"])

    def heading(self, col, text=None, command=None):
        if text is not None and col in self.header_cells:
            self.header_cells[col].configure(text=text)
        if command is not None:
            self._header_commands[col] = command

    def get_children(self):
        return list(self.row_widgets.keys())

    def delete(self, item):
        if item == "":
            self.clear()
            return
        data = self.row_widgets.pop(item, None)
        if data:
            data["frame"].destroy()
        self.row_data.pop(item, None)
        if item in self._ordered_iids:
            self._ordered_iids.remove(item)
        if self.selected_iid == item:
            self.selected_iid = None

    def clear(self):
        for iid in list(self.row_widgets.keys()):
            self.delete(iid)
        self._ordered_iids = []

    def insert(self, parent, index, iid=None, values=(), tags=()):
        self.insert_row(iid, values, tags=tags)

    def insert_row(self, iid, values, tags=(), row_index=None):
        if row_index is None:
            row_index = len(self.row_widgets)
        tags = tuple(tags or ())
        bg, fg = _tag_colors(tags)
        row = ctk.CTkFrame(self.scroll, fg_color=bg, corner_radius=0)
        row.grid(row=row_index, column=0, sticky="ew", padx=0, pady=0)

        labels = {}
        for idx, col in enumerate(self.columns):
            stretch = self._col_stretch_fn(col)
            row.grid_columnconfigure(idx, weight=1 if stretch else 0, minsize=self._col_width_fn(col))
            text = str(values[idx]) if idx < len(values) else ""
            anchor = self._cell_anchor(col)
            font = MONO_FONT if col == "value" else self.ui_font_sm
            kwargs = {
                "text": text,
                "font": font,
                "text_color": fg,
                "fg_color": "transparent",
                "anchor": anchor,
                "justify": "left" if anchor != "center" else "center",
            }
            if self._col_wrap_fn(col) and text.strip():
                kwargs["wraplength"] = self._wraplength_for(col)
            lbl = ctk.CTkLabel(row, **kwargs)
            lbl.grid(row=0, column=idx, sticky=self._cell_sticky(col), padx=4, pady=3)
            labels[col] = lbl

        self._mark_row_widget(row, iid)
        self._wire_row_events(row)
        self.row_data[iid] = tuple(values)
        self.row_widgets[iid] = {"frame": row, "labels": labels, "bg": bg, "fg": fg}
        if not self._batch:
            self.container.after_idle(self._update_wraplengths)

    def _update_row(self, iid, values, tags, row_index):
        values = tuple(values)
        tags = tuple(tags or ())
        bg, fg = _tag_colors(tags)
        data = self.row_widgets[iid]
        selected = iid == self.selected_iid
        if (
            not selected
            and self.row_data.get(iid) == values
            and data["bg"] == bg
            and data["fg"] == fg
        ):
            data["frame"].grid(row=row_index, column=0, sticky="ew", padx=0, pady=0)
            return
        display_bg = "#1f538d" if selected else bg
        display_fg = "#ffffff" if selected else fg

        data["frame"].configure(fg_color=display_bg)
        data["frame"].grid(row=row_index, column=0, sticky="ew", padx=0, pady=0)
        data["bg"] = bg
        data["fg"] = fg

        for idx, col in enumerate(self.columns):
            text = str(values[idx]) if idx < len(values) else ""
            lbl = data["labels"][col]
            lbl.configure(
                text=text,
                text_color=display_fg,
                fg_color=display_bg if selected else "transparent",
            )
            if self._col_wrap_fn(col):
                lbl.configure(wraplength=self._wraplength_for(col) if text.strip() else 0)

        self.row_data[iid] = values

    def _reindex_rows(self):
        for row_index, iid in enumerate(self._ordered_iids):
            data = self.row_widgets.get(iid)
            if data:
                data["frame"].grid(row=row_index, column=0, sticky="ew", padx=0, pady=0)

    def sync_rows(self, entries):
        self._batch = True
        try:
            new_iids = set()
            ordered = []
            for row_index, (iid, values, tags) in enumerate(entries):
                new_iids.add(iid)
                ordered.append(iid)
                if iid in self.row_widgets:
                    self._update_row(iid, values, tags, row_index)
                else:
                    self.insert_row(iid, values, tags=tags, row_index=row_index)
            for iid in list(self.row_widgets.keys()):
                if iid not in new_iids:
                    self.delete(iid)
            self._ordered_iids = ordered
            self._reindex_rows()
        finally:
            self._batch = False
            self._update_wraplengths()

    def _mark_row_widget(self, widget, iid):
        widget._row_iid = iid
        for child in widget.winfo_children():
            self._mark_row_widget(child, iid)

    def selection(self):
        return (self.selected_iid,) if self.selected_iid else ()

    def selection_set(self, iid):
        selected_bg = "#1f538d"
        if self.selected_iid and self.selected_iid in self.row_widgets:
            prev = self.row_widgets[self.selected_iid]
            prev["frame"].configure(fg_color=prev["bg"])
            for lbl in prev["labels"].values():
                lbl.configure(text_color=prev["fg"], fg_color="transparent")
        self.selected_iid = iid
        if iid in self.row_widgets:
            row = self.row_widgets[iid]
            row["frame"].configure(fg_color=selected_bg)
            for lbl in row["labels"].values():
                lbl.configure(text_color="#ffffff", fg_color=selected_bg)

    def item(self, iid):
        return {"values": self.row_data.get(iid, ())}

    def row_at_event(self, event):
        widget = event.widget
        while widget is not None:
            iid = getattr(widget, "_row_iid", None)
            if iid:
                return iid
            if widget in (self.container, self.scroll, self.scroll._parent_frame, self.scroll._parent_canvas):
                break
            widget = widget.master
        x, y = event.x_root, event.y_root
        widget = self.scroll.winfo_containing(x, y)
        while widget is not None:
            iid = getattr(widget, "_row_iid", None)
            if iid:
                return iid
            if widget in (self.container, self.scroll, self.scroll._parent_frame, self.scroll._parent_canvas):
                break
            widget = widget.master
        return ""

    def column_at_event(self, event):
        rel_x = event.x_root - self.header.winfo_rootx()
        if rel_x < 0:
            return ""
        pos = 0
        for idx, col in enumerate(self.columns):
            cell = self.header_cells.get(col)
            width = cell.winfo_width() if cell else self._col_width_fn(col)
            if rel_x < pos + width:
                return f"#{idx + 1}"
            pos += width
        return f"#{len(self.columns)}"

    def region_at_event(self, event):
        return "cell" if self.row_at_event(event) else "nothing"

    def identify_row(self, y):
        return self.selected_iid or ""

    def identify_column(self, x):
        return "#1"

    def identify_region(self, x, y):
        return "cell"


def ensure_app_icon(root):
    icon_path = Path(__file__).parent / "assets" / "icon.png"
    icon_path.parent.mkdir(exist_ok=True)
    if not icon_path.is_file():
        try:
            from PIL import Image, ImageDraw

            img = Image.new("RGBA", (64, 64), (31, 83, 141, 255))
            draw = ImageDraw.Draw(img)
            draw.rounded_rectangle((8, 8, 56, 56), radius=10, fill=(46, 134, 222, 255))
            draw.text((20, 18), "R", fill="white")
            img.save(icon_path)
        except Exception:
            return None
    try:
        from PIL import Image, ImageTk

        img = Image.open(icon_path)
        photo = ImageTk.PhotoImage(img)
        root.iconphoto(True, photo)
        root._app_icon = photo
        return str(icon_path)
    except Exception:
        return None
