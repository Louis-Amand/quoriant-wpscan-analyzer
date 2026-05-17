"""Interface graphique : saisie du token, de l'URL et lancement du scan."""

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk

from . import config
from .report import generate_report
from .runner import WPScanError, prepare, run_scan


def _normalize_url(url: str) -> str:
    url = url.strip()
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _open_path(path: str) -> None:
    """Ouvre un fichier ou dossier avec l'application par défaut de l'OS."""
    try:
        if sys.platform == "win32":
            os.startfile(path)  # noqa: S606
        elif sys.platform == "darwin":
            subprocess.run(["open", path], check=False)
        else:
            subprocess.run(["xdg-open", path], check=False)
    except OSError:
        pass


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.queue: queue.Queue = queue.Queue()
        self.last_report: str | None = None
        self.scanning = False

        root.title("WPScan Analyzer")
        root.geometry("640x560")
        root.minsize(560, 480)

        cfg = config.load()
        pad = {"padx": 14, "pady": 4}

        tk.Label(root, text="WPScan Analyzer", font=("Helvetica", 16, "bold")).pack(
            anchor="w", padx=14, pady=(12, 0)
        )
        tk.Label(
            root,
            text="Scannez un site WordPress et obtenez un rapport PDF.",
            fg="#666",
        ).pack(anchor="w", padx=14, pady=(0, 8))

        form = tk.Frame(root)
        form.pack(fill="x", **pad)
        form.columnconfigure(1, weight=1)

        # Token
        tk.Label(form, text="Token WPScan").grid(row=0, column=0, sticky="w", pady=4)
        self.token_var = tk.StringVar(value=cfg["token"])
        self.token_entry = tk.Entry(form, textvariable=self.token_var, show="*")
        self.token_entry.grid(row=0, column=1, sticky="ew", padx=(8, 8))
        self.remember_var = tk.BooleanVar(value=cfg["remember_token"])
        tk.Checkbutton(form, text="Mémoriser", variable=self.remember_var).grid(
            row=0, column=2, sticky="w"
        )

        # URL
        tk.Label(form, text="URL du site").grid(row=1, column=0, sticky="w", pady=4)
        self.url_var = tk.StringVar()
        tk.Entry(form, textvariable=self.url_var).grid(
            row=1, column=1, columnspan=2, sticky="ew", padx=(8, 0)
        )

        # Dossier de destination
        tk.Label(form, text="Dossier du rapport").grid(
            row=2, column=0, sticky="w", pady=4
        )
        self.dir_var = tk.StringVar(value=cfg["output_dir"])
        tk.Entry(form, textvariable=self.dir_var).grid(
            row=2, column=1, sticky="ew", padx=(8, 8)
        )
        tk.Button(form, text="Parcourir...", command=self._choose_dir).grid(
            row=2, column=2, sticky="ew"
        )

        # Lien d'aide pour le token
        link = tk.Label(
            root,
            text="Obtenir un token gratuit sur wpscan.com/api",
            fg="#1a6fc4",
            cursor="hand2",
        )
        link.pack(anchor="w", padx=14)
        link.bind("<Button-1>", lambda _e: _open_path("https://wpscan.com/api"))

        # Actions
        actions = tk.Frame(root)
        actions.pack(fill="x", **pad)
        self.scan_btn = tk.Button(
            actions,
            text="Lancer le scan",
            font=("Helvetica", 11, "bold"),
            command=self._start_scan,
        )
        self.scan_btn.pack(side="left")
        self.open_btn = tk.Button(
            actions, text="Ouvrir le rapport", command=self._open_report,
            state="disabled",
        )
        self.open_btn.pack(side="left", padx=8)

        self.progress = ttk.Progressbar(root, mode="indeterminate")
        self.progress.pack(fill="x", padx=14, pady=(4, 0))

        # Journal
        tk.Label(root, text="Journal", fg="#666").pack(anchor="w", padx=14, pady=(8, 0))
        self.log_box = scrolledtext.ScrolledText(root, height=10, state="disabled")
        self.log_box.pack(fill="both", expand=True, padx=14, pady=(0, 12))

        self._log("Prêt. Renseignez le token et l'URL puis lancez le scan.")
        self.root.after(120, self._drain_queue)

    # --- Interface ---------------------------------------------------------
    def _choose_dir(self):
        chosen = filedialog.askdirectory(initialdir=self.dir_var.get() or os.getcwd())
        if chosen:
            self.dir_var.set(chosen)

    def _log(self, message: str):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", message + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _open_report(self):
        if self.last_report and os.path.exists(self.last_report):
            _open_path(self.last_report)

    # --- Cycle de scan -----------------------------------------------------
    def _start_scan(self):
        if self.scanning:
            return
        token = self.token_var.get().strip()
        url = _normalize_url(self.url_var.get())
        out_dir = self.dir_var.get().strip()

        if not token:
            self._log("⚠ Veuillez renseigner le token WPScan.")
            return
        if not url:
            self._log("⚠ Veuillez renseigner l'URL du site.")
            return
        if not os.path.isdir(out_dir):
            self._log("⚠ Le dossier de destination est introuvable.")
            return

        config.save(token, out_dir, self.remember_var.get())
        self.url_var.set(url)

        self.scanning = True
        self.scan_btn.configure(state="disabled", text="Scan en cours...")
        self.open_btn.configure(state="disabled")
        self.progress.start(12)
        self._log("-" * 50)

        threading.Thread(
            target=self._worker, args=(token, url, out_dir), daemon=True
        ).start()

    def _worker(self, token, url, out_dir):
        """Exécuté dans un thread : aucune interaction Tkinter directe ici."""
        log = lambda m: self.queue.put(("log", m))  # noqa: E731
        try:
            engine = prepare(log)
            data = run_scan(engine, url, token, log)
            path = generate_report(data, out_dir)
            self.queue.put(("done", path))
        except WPScanError as exc:
            self.queue.put(("error", str(exc)))
        except Exception as exc:  # garde-fou : ne jamais bloquer l'UI
            self.queue.put(("error", f"Erreur inattendue : {exc}"))

    def _drain_queue(self):
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "log":
                    self._log(payload)
                elif kind == "done":
                    self._finish(ok=True, payload=payload)
                elif kind == "error":
                    self._finish(ok=False, payload=payload)
        except queue.Empty:
            pass
        self.root.after(120, self._drain_queue)

    def _finish(self, ok: bool, payload: str):
        self.scanning = False
        self.progress.stop()
        self.scan_btn.configure(state="normal", text="Lancer le scan")
        if ok:
            self.last_report = payload
            self.open_btn.configure(state="normal")
            self._log(f"✔ Rapport PDF généré : {payload}")
            _open_path(os.path.dirname(payload))
        else:
            for line in payload.splitlines():
                self._log("✖ " + line)


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
