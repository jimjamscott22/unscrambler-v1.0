"""Tkinter desktop app for fast anagram solving."""

from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from models import IndexBuildResult, SolveOptions, SolveReport
from solver import AnagramSolver
from utils import export_report, load_config, save_config, setup_logging


class UnscramblerApp(tk.Tk):
    """Desktop UI for loading wordlists and solving scrambled words."""

    def __init__(self) -> None:
        super().__init__()
        setup_logging()
        self.logger = logging.getLogger(__name__)

        self.title("Anagram Unscrambler")
        self.geometry("1200x780")
        self.minsize(1000, 650)

        self.solver = AnagramSolver()
        self.current_report: SolveReport | None = None
        self.manual_choices: dict[int, str] = {}
        self.indexing_thread: threading.Thread | None = None
        self.worker_queue: queue.Queue[tuple] = queue.Queue()
        self.is_indexing = False

        self.config_data = load_config()
        self._build_vars()
        self._build_ui()
        self.after(100, self._poll_worker_queue)

    def _build_vars(self) -> None:
        self.wordlist_var = tk.StringVar(value=self.config_data.get("last_wordlist_path", ""))
        self.normalize_case_var = tk.BooleanVar(value=True)
        self.strip_non_alnum_var = tk.BooleanVar(value=False)
        self.auto_detect_var = tk.BooleanVar(value=False)
        self.speed_cache_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Load a wordlist to build the index.")
        self.answer_var = tk.StringVar(value="")

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        top = ttk.Frame(self, padding=8)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="Wordlist (.txt):").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.wordlist_entry = ttk.Entry(top, textvariable=self.wordlist_var)
        self.wordlist_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8))
        ttk.Button(top, text="Browse", command=self._browse_wordlist).grid(row=0, column=2, padx=(0, 8))
        self.index_button = ttk.Button(top, text="Load + Index", command=self._start_indexing)
        self.index_button.grid(row=0, column=3)

        options = ttk.LabelFrame(self, text="Options", padding=8)
        options.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 6))
        ttk.Checkbutton(options, text="Normalize case", variable=self.normalize_case_var).grid(row=0, column=0, sticky="w", padx=(0, 12))
        ttk.Checkbutton(options, text="Strip non-alphanumerics", variable=self.strip_non_alnum_var).grid(row=0, column=1, sticky="w", padx=(0, 12))
        ttk.Checkbutton(options, text="Auto-detect labels", variable=self.auto_detect_var).grid(row=0, column=2, sticky="w", padx=(0, 12))
        ttk.Checkbutton(options, text="Speed mode (cache index)", variable=self.speed_cache_var).grid(row=0, column=3, sticky="w")

        middle = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        middle.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 6))
        self.rowconfigure(2, weight=1)

        input_frame = ttk.LabelFrame(middle, text="Scrambled Input", padding=8)
        input_frame.columnconfigure(0, weight=1)
        input_frame.rowconfigure(0, weight=1)
        self.input_text = ScrolledText(input_frame, wrap=tk.WORD, font=("Segoe UI", 11), height=12)
        self.input_text.grid(row=0, column=0, sticky="nsew")
        input_buttons = ttk.Frame(input_frame)
        input_buttons.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        ttk.Button(input_buttons, text="Solve", command=self._solve_clicked).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(input_buttons, text="Clear", command=self._clear_input_and_results).grid(row=0, column=1)

        results_frame = ttk.LabelFrame(middle, text="Per-Token Results", padding=8)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        self.results_tree = ttk.Treeview(
            results_frame,
            columns=("token", "status", "chosen", "alts"),
            show="headings",
            height=14,
        )
        self.results_tree.heading("token", text="Token")
        self.results_tree.heading("status", text="Status")
        self.results_tree.heading("chosen", text="Chosen Match")
        self.results_tree.heading("alts", text="Alternative Matches")
        self.results_tree.column("token", width=180, anchor=tk.W)
        self.results_tree.column("status", width=90, anchor=tk.W)
        self.results_tree.column("chosen", width=240, anchor=tk.W)
        self.results_tree.column("alts", width=140, anchor=tk.CENTER)
        tree_scroll = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=tree_scroll.set)
        self.results_tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.results_tree.bind("<<TreeviewSelect>>", self._on_result_selected)

        alt_frame = ttk.Frame(results_frame)
        alt_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        alt_frame.columnconfigure(0, weight=1)
        ttk.Label(alt_frame, text="Alternative matches for selected token:").grid(row=0, column=0, sticky="w")
        self.alt_listbox = tk.Listbox(alt_frame, height=5, exportselection=False)
        self.alt_listbox.grid(row=1, column=0, sticky="ew", pady=(4, 6))
        ttk.Button(alt_frame, text="Use Selected Match", command=self._apply_selected_match).grid(row=2, column=0, sticky="w")

        middle.add(input_frame, weight=1)
        middle.add(results_frame, weight=2)

        bottom = ttk.Frame(self, padding=8)
        bottom.grid(row=3, column=0, sticky="ew")
        bottom.columnconfigure(1, weight=1)
        ttk.Label(bottom, text="Answer (CSV):").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.answer_entry = ttk.Entry(bottom, textvariable=self.answer_var)
        self.answer_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8))
        ttk.Button(bottom, text="Copy Answer", command=self._copy_answer).grid(row=0, column=2, padx=(0, 8))
        ttk.Button(bottom, text="Save Results", command=self._save_results).grid(row=0, column=3)

        status_row = ttk.Frame(self, padding=(8, 0, 8, 8))
        status_row.grid(row=4, column=0, sticky="ew")
        status_row.columnconfigure(1, weight=1)
        ttk.Label(status_row, text="Status:").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Label(status_row, textvariable=self.status_var).grid(row=0, column=1, sticky="w")
        self.progress = ttk.Progressbar(status_row, orient=tk.HORIZONTAL, length=220, mode="determinate", maximum=100)
        self.progress.grid(row=0, column=2, sticky="e")

    def _browse_wordlist(self) -> None:
        path = filedialog.askopenfilename(
            title="Select wordlist file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            self.wordlist_var.set(path)

    def _start_indexing(self) -> None:
        if self.is_indexing:
            return

        path = self.wordlist_var.get().strip()
        if not path:
            messagebox.showerror("Missing wordlist", "Please select a wordlist file first.")
            return
        resolved = str(Path(path).resolve())
        if not Path(resolved).exists():
            messagebox.showerror("File not found", f"Wordlist does not exist:\n{path}")
            return
        self.wordlist_var.set(resolved)

        options = self._current_options()
        self.is_indexing = True
        self.progress.configure(value=0)
        self.status_var.set("Indexing wordlist in background...")
        self.index_button.configure(state=tk.DISABLED)

        self.indexing_thread = threading.Thread(
            target=self._build_index_worker,
            args=(resolved, options),
            daemon=True,
        )
        self.indexing_thread.start()

    def _build_index_worker(self, path: str, options: SolveOptions) -> None:
        try:
            result = self.solver.build_index(
                wordlist_path=path,
                options=options,
                progress_callback=lambda pct: self.worker_queue.put(("progress", pct)),
            )
            self.worker_queue.put(("index_done", result))
        except Exception as exc:
            self.logger.exception("Failed building index")
            self.worker_queue.put(("error", f"Failed to build index: {exc}"))

    def _poll_worker_queue(self) -> None:
        try:
            while True:
                event = self.worker_queue.get_nowait()
                kind = event[0]
                if kind == "progress":
                    pct = max(0.0, min(float(event[1]), 1.0))
                    self.progress.configure(value=int(pct * 100))
                elif kind == "index_done":
                    self._handle_index_done(event[1])
                elif kind == "error":
                    self._handle_worker_error(event[1])
        except queue.Empty:
            pass
        finally:
            self.after(100, self._poll_worker_queue)

    def _handle_index_done(self, result: IndexBuildResult) -> None:
        self.is_indexing = False
        self.index_button.configure(state=tk.NORMAL)
        self.progress.configure(value=100)

        source = "cache" if result.loaded_from_cache else "wordlist"
        self.status_var.set(
            f"Index ready from {source}: {result.accepted_words} words, "
            f"{result.unique_signatures} signatures."
        )
        self.config_data["last_wordlist_path"] = result.wordlist_path
        save_config(self.config_data)

    def _handle_worker_error(self, message: str) -> None:
        self.is_indexing = False
        self.index_button.configure(state=tk.NORMAL)
        self.progress.configure(value=0)
        self.status_var.set("Indexing failed.")
        messagebox.showerror("Indexing error", message)

    def _current_options(self) -> SolveOptions:
        return SolveOptions(
            normalize_case=self.normalize_case_var.get(),
            strip_non_alphanumerics=self.strip_non_alnum_var.get(),
            auto_detect_labels=self.auto_detect_var.get(),
            use_speed_cache=self.speed_cache_var.get(),
        )

    def _solve_clicked(self) -> None:
        self.manual_choices = {}
        self._run_solve()

    def _run_solve(self) -> None:
        if self.is_indexing:
            messagebox.showinfo("Indexing in progress", "Please wait for indexing to finish.")
            return
        if not self.solver.index:
            messagebox.showerror("No index", "Please load and index a wordlist before solving.")
            return
        current_wordlist = self.wordlist_var.get().strip()
        if current_wordlist and str(Path(current_wordlist).resolve()) != str(Path(self.solver.wordlist_path).resolve()):
            messagebox.showwarning(
                "Re-index required",
                "Selected wordlist differs from the indexed wordlist. Rebuild index first.",
            )
            return

        options = self._current_options()
        if (
            options.normalize_case != self.solver.index_options.normalize_case
            or options.strip_non_alphanumerics != self.solver.index_options.strip_non_alphanumerics
        ):
            messagebox.showwarning(
                "Re-index required",
                "Normalization options changed since indexing. Rebuild the index with current options first.",
            )
            return

        raw_input = self.input_text.get("1.0", tk.END)
        if not raw_input.strip():
            messagebox.showinfo("Empty input", "Paste scrambled words in the input area first.")
            return

        try:
            report = self.solver.solve(raw_input, options=options, manual_choices=self.manual_choices)
            self.current_report = report
            self._render_results(report)
            self.answer_var.set(report.answer_csv)
            if report.results:
                self.status_var.set(f"Solved {len(report.results)} tokens.")
            else:
                self.status_var.set("No valid tokens were parsed from input.")
                messagebox.showinfo("No tokens found", "Input did not produce any tokens after parsing.")
        except Exception as exc:
            self.logger.exception("Solve failed")
            messagebox.showerror("Solve error", f"Could not solve input: {exc}")

    def _render_results(self, report: SolveReport) -> None:
        self.results_tree.delete(*self.results_tree.get_children())
        self.alt_listbox.delete(0, tk.END)

        for idx, row in enumerate(report.results):
            alt_count = max(0, len(row.matches) - 1)
            self.results_tree.insert(
                "",
                tk.END,
                iid=str(idx),
                values=(row.token, row.status, row.chosen_match, alt_count),
            )

    def _on_result_selected(self, _event: object) -> None:
        self.alt_listbox.delete(0, tk.END)
        if not self.current_report:
            return
        selected = self.results_tree.selection()
        if not selected:
            return
        idx = int(selected[0])
        result = self.current_report.results[idx]
        alternatives = [word for word in result.matches if word != result.chosen_match]
        for alt in alternatives:
            self.alt_listbox.insert(tk.END, alt)

    def _apply_selected_match(self) -> None:
        if not self.current_report:
            return
        selected_row = self.results_tree.selection()
        selected_alt = self.alt_listbox.curselection()
        if not selected_row or not selected_alt:
            return

        idx = int(selected_row[0])
        choice = self.alt_listbox.get(selected_alt[0])
        self.manual_choices[idx] = choice
        self._run_solve()

    def _copy_answer(self) -> None:
        answer = self.answer_var.get().strip()
        if not answer:
            messagebox.showinfo("No answer", "No answer available to copy yet.")
            return
        self.clipboard_clear()
        self.clipboard_append(answer)
        self.update_idletasks()
        self.status_var.set("Answer copied to clipboard.")

    def _save_results(self) -> None:
        if not self.current_report:
            messagebox.showinfo("No results", "Solve at least once before exporting.")
            return

        json_path_str = filedialog.asksaveasfilename(
            title="Save results JSON (CSV will be saved alongside)",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not json_path_str:
            return

        json_path = Path(json_path_str)
        csv_path = json_path.with_suffix(".csv")

        try:
            export_report(
                json_path=json_path,
                csv_path=csv_path,
                report=self.current_report,
                wordlist_path=self.solver.wordlist_path,
                options=self._current_options(),
            )
            self.status_var.set(f"Saved: {json_path.name} and {csv_path.name}")
            messagebox.showinfo("Export complete", f"Saved:\n{json_path}\n{csv_path}")
        except Exception as exc:
            self.logger.exception("Export failed")
            messagebox.showerror("Export error", f"Could not save results: {exc}")

    def _clear_input_and_results(self) -> None:
        self.input_text.delete("1.0", tk.END)
        self.results_tree.delete(*self.results_tree.get_children())
        self.alt_listbox.delete(0, tk.END)
        self.answer_var.set("")
        self.current_report = None
        self.manual_choices = {}
        self.status_var.set("Cleared input and results.")


def main() -> None:
    app = UnscramblerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
