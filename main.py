import customtkinter as ctk
from tkinter import ttk
import threading
import time
import webbrowser   # ✅ FIX: required for opening browser


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class ReconDashboard(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("Recon Intelligence Dashboard")
        self.geometry("1250x750")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ---------------- SIDEBAR ----------------
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=15)
        self.sidebar.grid(row=0, column=0, sticky="ns", padx=10, pady=10)

        ctk.CTkLabel(
            self.sidebar,
            text="RECON ENGINE",
            font=("Arial", 22, "bold")
        ).pack(pady=20)

        self.target_entry = ctk.CTkEntry(self.sidebar, placeholder_text="Enter target domain")
        self.target_entry.pack(pady=10, padx=10, fill="x")

        self.start_btn = ctk.CTkButton(
            self.sidebar,
            text="Start Full Scan",
            command=self.start_scan_thread
        )
        self.start_btn.pack(pady=10, padx=10, fill="x")

        # ---------------- TOOL STATUS PANEL ----------------
        self.tool_frame = ctk.CTkFrame(self.sidebar)
        self.tool_frame.pack(pady=15, padx=10, fill="x")

        ctk.CTkLabel(self.tool_frame, text="Tool Status", font=("Arial", 16, "bold")).pack(pady=5)

        self.tools = {
            "Subfinder": "Pending",
            "Amass": "Pending",
            "Assetfinder": "Pending",
            "Wayback": "Pending",
            "HTTP Probe": "Pending",
            "FFUF": "Pending"
        }

        self.tool_labels = {}

        for tool in self.tools:
            label = ctk.CTkLabel(self.tool_frame, text=f"{tool}: ⏳ Pending")
            label.pack(anchor="w", padx=10, pady=2)
            self.tool_labels[tool] = label

        # ---------------- MAIN AREA ----------------
        self.main = ctk.CTkFrame(self, corner_radius=15)
        self.main.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

        self.main.grid_rowconfigure(1, weight=1)
        self.main.grid_columnconfigure(0, weight=1)

        # header
        self.header = ctk.CTkFrame(self.main)
        self.header.grid(row=0, column=0, sticky="ew", padx=10, pady=10)

        self.status_label = ctk.CTkLabel(
            self.header,
            text="Status: Idle",
            font=("Arial", 16)
        )
        self.status_label.pack(side="left", padx=10)

        self.active_tool = ctk.CTkLabel(
            self.header,
            text="Active Tool: None",
            font=("Arial", 14)
        )
        self.active_tool.pack(side="right", padx=10)

        # ---------------- TABLE ----------------
        self.table = ttk.Treeview(
            self.main,
            columns=("subdomain", "status", "ip"),
            show="headings"
        )

        self.table.heading("subdomain", text="Subdomain")
        self.table.heading("status", text="Status")
        self.table.heading("ip", text="IP")

        self.table.grid(row=1, column=0, sticky="nsew", padx=10)

        # ✅ FIX: bind click event
        self.table.bind("<Double-1>", self.on_row_click)

        # ---------------- LOGS ----------------
        self.logs = ctk.CTkTextbox(self.main, height=140)
        self.logs.grid(row=2, column=0, sticky="ew", padx=10, pady=10)

        self.sub_count = 0

    # ---------------- CLICK OPEN ----------------
    def on_row_click(self, event):
        selected_item = self.table.selection()

        if not selected_item:
            return

        row = self.table.item(selected_item[0])["values"]
        subdomain = row[0]

        url = f"https://{subdomain}"

        self.log(f"[OPEN] {url}")

        try:
            webbrowser.open(url)
        except Exception as e:
            self.log(f"[ERROR] {e}")

    # ---------------- SCAN ENGINE ----------------
    def start_scan_thread(self):
        t = threading.Thread(target=self.run_scan)
        t.start()

    def set_tool(self, tool, status):
        emoji = {
            "Running": "🟡",
            "Done": "🟢",
            "Pending": "⏳"
        }

        self.tool_labels[tool].configure(
            text=f"{tool}: {emoji[status]} {status}"
        )
        self.tools[tool] = status

    def run_scan(self):
        domain = self.target_entry.get()
        if not domain:
            return

        self.update_status("Starting scan")

        self.run_tool("Subfinder", domain, ["api."+domain, "dev."+domain])
        self.run_tool("Amass", domain, ["admin."+domain, "mail."+domain])
        self.run_tool("Assetfinder", domain, ["test."+domain])
        self.run_tool("Wayback", domain, ["old."+domain, "blog."+domain])
        self.run_tool("HTTP Probe", domain, ["api."+domain, "dev."+domain])
        self.run_tool("FFUF", domain, ["admin."+domain+"/login"])

        self.update_status("Scan Completed")

    def run_tool(self, tool, domain, results):
        self.set_tool(tool, "Running")
        self.active_tool.configure(text=f"Active Tool: {tool}")

        self.log(f"[+] Running {tool} on {domain}")

        time.sleep(1)

        for r in results:
            self.table.insert("", "end", values=(r, "200", "1.1.1.1"))
            self.log(f"[{tool}] Found: {r}")
            self.sub_count += 1

        self.set_tool(tool, "Done")
        self.log(f"[-] Finished {tool}")

    # ---------------- UI HELPERS ----------------
    def update_status(self, text):
        self.status_label.configure(text=f"Status: {text}")

    def log(self, msg):
        self.logs.insert("end", msg + "\n")
        self.logs.see("end")


if __name__ == "__main__":
    app = ReconDashboard()
    app.mainloop()