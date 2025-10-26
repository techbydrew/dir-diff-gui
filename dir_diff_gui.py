#!/usr/bin/env python3
"""
dir_diff.py — Folder difference tool with Tkinter UI and JSON/TXT export
Author: Andrew Ramos

Behavior:
 - Choose Left and Right folders with Browse...
 - Comparison **automatically** starts once both folders are selected (and can be started manually with Compare)
 - Tabs: Text view (human readable) and JSON view (pretty-printed)
 - Save JSON and Save TXT buttons to export results
 - Background thread for hashing so the UI stays responsive
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
import hashlib
import json
import threading
import queue
import time
import sys
import os

CHUNK = 8192

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()

def walk_files(root: Path):
    """Return sorted list of files (Path objects) under root (recursive)."""
    return sorted([p for p in root.rglob("*") if p.is_file()])

class DirDiffWorker(threading.Thread):
    """Background worker that computes diffs and emits progress/status via a queue."""
    def __init__(self, left: Path, right: Path, out_queue: queue.Queue):
        super().__init__(daemon=True)
        self.left = left
        self.right = right
        self.q = out_queue

    def run(self):
        try:
            self.q.put(("status", "Scanning files..."))
            a_files = walk_files(self.left)
            b_files = walk_files(self.right)
            self.q.put(("status", f"Found {len(a_files)} files on left, {len(b_files)} files on right."))

            a_rel = {p.relative_to(self.left): p for p in a_files}
            b_rel = {p.relative_to(self.right): p for p in b_files}

            only_left = sorted([str(p) for p in (set(a_rel.keys()) - set(b_rel.keys()))])
            only_right = sorted([str(p) for p in (set(b_rel.keys()) - set(a_rel.keys()))])
            in_both = sorted(list(set(a_rel.keys()) & set(b_rel.keys())))

            self.q.put(("status", f"Hashing {len(in_both)} files that exist in both folders..."))
            diff = []
            same = []
            total = len(in_both)
            for idx, rel in enumerate(in_both, start=1):
                lpath = a_rel[rel]
                rpath = b_rel[rel]
                # compute hashes
                h1 = sha256(lpath)
                h2 = sha256(rpath)
                if h1 == h2:
                    same.append(str(rel))
                else:
                    diff.append(str(rel))
                # update progress occasionally
                if total > 0 and (idx % max(1, total // 20) == 0 or idx == total):
                    self.q.put(("progress", {"current": idx, "total": total}))
            result = {
                "only_left": only_left,
                "only_right": only_right,
                "different_content": diff,
                "identical": same,
                "left_root": str(self.left),
                "right_root": str(self.right),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.q.put(("done", result))
        except Exception as e:
            self.q.put(("error", str(e)))

class DirDiffApp:
    def __init__(self, root):
        self.root = root
        root.title("Directory Diff (SHA-256)")
        # Make sure window appears on-screen
        try:
            root.eval('tk::PlaceWindow %s center' % root.winfo_pathname(root.winfo_id()))
        except Exception:
            pass

        # Frame: selectors
        frm_select = ttk.Frame(root, padding=(10,10))
        frm_select.grid(row=0, column=0, sticky="ew")
        frm_select.columnconfigure(1, weight=1)

        ttk.Label(frm_select, text="Left folder:").grid(row=0, column=0, sticky="w")
        self.left_var = tk.StringVar()
        self.left_entry = ttk.Entry(frm_select, textvariable=self.left_var)
        self.left_entry.grid(row=0, column=1, sticky="ew", padx=(5,5))
        ttk.Button(frm_select, text="Browse...", command=self.browse_left).grid(row=0, column=2, padx=(5,0))

        ttk.Label(frm_select, text="Right folder:").grid(row=1, column=0, sticky="w")
        self.right_var = tk.StringVar()
        self.right_entry = ttk.Entry(frm_select, textvariable=self.right_var)
        self.right_entry.grid(row=1, column=1, sticky="ew", padx=(5,5))
        ttk.Button(frm_select, text="Browse...", command=self.browse_right).grid(row=1, column=2, padx=(5,0))

        # Buttons
        btn_frame = ttk.Frame(root, padding=(10,5))
        btn_frame.grid(row=1, column=0, sticky="ew")
        btn_frame.columnconfigure(0, weight=1)

        self.compare_btn = ttk.Button(btn_frame, text="Compare Now", command=self.start_compare)
        self.compare_btn.grid(row=0, column=0, sticky="w")
        self.save_json_btn = ttk.Button(btn_frame, text="Save JSON...", command=self.save_json, state="disabled")
        self.save_json_btn.grid(row=0, column=1, sticky="e", padx=(5,0))
        self.save_txt_btn = ttk.Button(btn_frame, text="Save TXT...", command=self.save_txt, state="disabled")
        self.save_txt_btn.grid(row=0, column=2, sticky="e", padx=(5,0))

        # Status / progress
        status_frame = ttk.Frame(root, padding=(10,5))
        status_frame.grid(row=2, column=0, sticky="ew")
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(status_frame, textvariable=self.status_var).grid(row=0, column=0, sticky="w")
        self.progress_var = tk.StringVar(value="")
        ttk.Label(status_frame, textvariable=self.progress_var).grid(row=0, column=1, sticky="e")

        # Tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0,10))
        root.rowconfigure(3, weight=1)
        root.columnconfigure(0, weight=1)

        # Text tab
        self.text_tab = ttk.Frame(self.notebook)
        self.text_widget = scrolledtext.ScrolledText(self.text_tab, wrap="none", height=24)
        self.text_widget.pack(fill="both", expand=True)
        self.notebook.add(self.text_tab, text="Text View")

        # JSON tab
        self.json_tab = ttk.Frame(self.notebook)
        self.json_widget = scrolledtext.ScrolledText(self.json_tab, wrap="none", height=24)
        self.json_widget.pack(fill="both", expand=True)
        self.notebook.add(self.json_tab, text="JSON View")

        # Queue for worker messages
        self.q = queue.Queue()
        self.worker = None
        self.result = None

        # Polling for queue messages
        self.root.after(200, self.check_queue)

        # If user types paths manually, attempt auto-compare when both present
        self.left_var.trace_add("write", lambda *a: self._auto_trigger())
        self.right_var.trace_add("write", lambda *a: self._auto_trigger())

    def browse_left(self):
        d = filedialog.askdirectory(title="Select LEFT folder")
        if d:
            self.left_var.set(d)

    def browse_right(self):
        d = filedialog.askdirectory(title="Select RIGHT folder")
        if d:
            self.right_var.set(d)

    def _auto_trigger(self):
        """If both folder fields are populated, start compare automatically."""
        left = self.left_var.get().strip()
        right = self.right_var.get().strip()
        if left and right:
            # small delay to avoid multiple triggers while user is selecting
            self.root.after(250, self._maybe_start_if_both_present)

    def _maybe_start_if_both_present(self):
        left = self.left_var.get().strip()
        right = self.right_var.get().strip()
        # only start if both still populated and no worker already running
        if left and right and (self.worker is None or not self.worker.is_alive()):
            self.start_compare()

    def start_compare(self):
        left = self.left_var.get().strip()
        right = self.right_var.get().strip()
        if not left or not right:
            messagebox.showwarning("Missing folder", "Please select both Left and Right folders.")
            return
        leftp = Path(left)
        rightp = Path(right)
        if not leftp.is_dir() or not rightp.is_dir():
            messagebox.showerror("Invalid folder", "Both selections must be directories.")
            return

        # disable buttons during work
        self.compare_btn.config(state="disabled")
        self.save_json_btn.config(state="disabled")
        self.save_txt_btn.config(state="disabled")
        self.status_var.set("Starting comparison...")
        self.progress_var.set("")
        self.text_widget.delete("1.0", tk.END)
        self.json_widget.delete("1.0", tk.END)
        self.result = None

        # start worker thread
        self.worker = DirDiffWorker(leftp, rightp, self.q)
        self.worker.start()

    def check_queue(self):
        """Poll queue for worker messages and update UI."""
        try:
            while True:
                item = self.q.get_nowait()
                typ = item[0]
                payload = item[1]
                if typ == "status":
                    self.status_var.set(payload)
                elif typ == "progress":
                    cur = payload.get("current", 0)
                    tot = payload.get("total", 0)
                    self.progress_var.set(f"Hashed {cur}/{tot}")
                elif typ == "done":
                    self.on_done(payload)
                elif typ == "error":
                    self.on_error(payload)
        except queue.Empty:
            pass
        finally:
            self.root.after(200, self.check_queue)

    def on_done(self, result):
        self.status_var.set("Done.")
        self.progress_var.set("")
        self.compare_btn.config(state="normal")
        self.save_json_btn.config(state="normal")
        self.save_txt_btn.config(state="normal")
        self.result = result
        # populate views
        self.populate_text_view(result)
        self.populate_json_view(result)
        # bring JSON tab to front as optional convenience
        # self.notebook.select(self.json_tab)

    def on_error(self, msg):
        self.status_var.set("Error.")
        self.compare_btn.config(state="normal")
        messagebox.showerror("Error during comparison", msg)

    def populate_text_view(self, res):
        sb = []
        sb.append("=== ONLY IN LEFT ===\n")
        if res["only_left"]:
            for p in res["only_left"]:
                sb.append(p + "\n")
        else:
            sb.append("(none)\n")
        sb.append("\n=== ONLY IN RIGHT ===\n")
        if res["only_right"]:
            for p in res["only_right"]:
                sb.append(p + "\n")
        else:
            sb.append("(none)\n")
        sb.append("\n=== DIFFERENT CONTENT ===\n")
        if res["different_content"]:
            for p in res["different_content"]:
                sb.append(p + "\n")
        else:
            sb.append("(none)\n")
        sb.append("\n=== IDENTICAL FILES ===\n")
        if res["identical"]:
            for p in res["identical"]:
                sb.append(p + "\n")
        else:
            sb.append("(none)\n")

        summary = f"Compared on: {res.get('timestamp')}\nLeft: {res['left_root']}\nRight: {res['right_root']}\n\n"
        self.text_widget.delete("1.0", tk.END)
        self.text_widget.insert(tk.END, summary + "".join(sb))
        self.text_widget.see("1.0")

    def populate_json_view(self, res):
        j = json.dumps(res, indent=2)
        self.json_widget.delete("1.0", tk.END)
        self.json_widget.insert(tk.END, j)
        self.json_widget.see("1.0")

    def save_json(self):
        if not self.result:
            messagebox.showwarning("No result", "No results to save. Run a comparison first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files","*.json"),("All files","*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.result, f, indent=2)
            messagebox.showinfo("Saved", f"Results saved to {path}")
        except Exception as e:
            messagebox.showerror("Save error", str(e))

    def save_txt(self):
        if not self.result:
            messagebox.showwarning("No result", "No results to save. Run a comparison first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if not path:
            return
        try:
            text = self.text_widget.get("1.0", tk.END)
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            messagebox.showinfo("Saved", f"Results saved to {path}")
        except Exception as e:
            messagebox.showerror("Save error", str(e))

def main():
    root = tk.Tk()
    # set window minimum size and position
    root.geometry("900x650")
    app = DirDiffApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
