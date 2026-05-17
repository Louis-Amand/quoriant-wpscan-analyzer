"""Interface graphique en 3 écrans : Accueil, Configuration, Progression."""

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk

from . import config
from .observatory import ObservatoryError, run_observatory
from .report import generate_report
from .runner import WPScanError, prepare, run_scan

# Étapes affichées pendant le scan (index -> libellé).
STEPS = [
    "Preparation de WPScan",
    "Analyse WordPress (WPScan)",
    "En-tetes HTTP (Mozilla Observatory)",
    "Generation du rapport PDF",
]

# Icône + couleur par état d'étape.
STEP_STYLE = {
    "pending": ("☐", "#999999"),   # case vide
    "running": ("▶", "#1a6fc4"),   # triangle bleu
    "done": ("☑", "#277a47"),      # case cochee verte
    "failed": ("✖", "#c0392b"),    # croix rouge
    "skipped": ("—", "#999999"),   # tiret
}


def _normalize_url(url: str) -> str:
    url = url.strip()
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _open_path(path: str) -> None:
    """Ouvre un fichier/dossier/URL avec l'application par défaut de l'OS."""
    try:
        if sys.platform == "win32":
            os.startfile(path)  # noqa: S606
        elif sys.platform == "darwin":
            subprocess.run(["open", path], check=False)
        else:
            subprocess.run(["xdg-open", path], check=False)
    except OSError:
        pass


class StepList(tk.Frame):
    """Liste d'étapes avec une case d'état qui évolue pendant le scan."""

    def __init__(self, master):
        super().__init__(master)
        self.rows = []
        for label in STEPS:
            row = tk.Frame(self)
            row.pack(fill="x", pady=3)
            icon = tk.Label(row, font=("Helvetica", 13), width=2)
            icon.pack(side="left")
            name = tk.Label(row, text=label, font=("Helvetica", 10), anchor="w")
            name.pack(side="left")
            self.rows.append((icon, name))
        self.reset()

    def reset(self):
        for i in range(len(self.rows)):
            self.set(i, "pending")

    def set(self, index: int, state: str):
        icon, name = self.rows[index]
        char, color = STEP_STYLE[state]
        icon.configure(text=char, fg=color)
        name.configure(fg="#222222" if state in ("running", "done") else "#777777")


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.queue: queue.Queue = queue.Queue()
        self.last_report: str | None = None
        self.scanning = False
        self.cfg = config.load()

        root.title("WPScan Analyzer")
        root.geometry("660x620")
        root.minsize(600, 560)

        self.container = tk.Frame(root)
        self.container.pack(fill="both", expand=True)
        self.container.rowconfigure(0, weight=1)
        self.container.columnconfigure(0, weight=1)

        self.welcome = self._build_welcome()
        self.config_screen = self._build_config()
        self.progress_screen = self._build_progress()
        for frame in (self.welcome, self.config_screen, self.progress_screen):
            frame.grid(row=0, column=0, sticky="nsew")

        self.welcome.tkraise()
        self.root.after(120, self._drain_queue)

    # --- Écran 1 : Accueil -------------------------------------------------
    def _build_welcome(self) -> tk.Frame:
        f = tk.Frame(self.container, padx=26, pady=22)
        tk.Label(f, text="WPScan Analyzer", font=("Helvetica", 20, "bold"),
                 fg="#212f47").pack(anchor="w")
        tk.Label(f, text="Analyse de securite pour vos sites WordPress.",
                 fg="#666").pack(anchor="w", pady=(0, 16))

        tk.Label(f, text="Sources utilisees pour le rapport :",
                 font=("Helvetica", 11, "bold")).pack(anchor="w")
        sources = [
            ("WPScan", "Vulnerabilites du coeur WordPress, du theme "
                       "et des extensions."),
            ("Mozilla HTTP Observatory", "Note de securite des en-tetes "
                                         "HTTP du site (A+ a F)."),
        ]
        for name, desc in sources:
            box = tk.Frame(f)
            box.pack(fill="x", pady=6)
            tk.Label(box, text="  •  " + name,
                     font=("Helvetica", 10, "bold"), fg="#212f47").pack(anchor="w")
            tk.Label(box, text="      " + desc, fg="#555",
                     justify="left").pack(anchor="w")

        tk.Label(
            f,
            text=("WPScan necessite un token gratuit (wpscan.com/api).\n"
                  "Sans token, seul le test Observatory est effectue."),
            fg="#777", justify="left",
        ).pack(anchor="w", pady=(14, 0))

        tk.Button(f, text="Commencer  >", font=("Helvetica", 11, "bold"),
                  command=lambda: self.config_screen.tkraise()).pack(
            anchor="w", pady=(22, 0))
        return f

    # --- Écran 2 : Configuration ------------------------------------------
    def _build_config(self) -> tk.Frame:
        f = tk.Frame(self.container, padx=26, pady=22)
        tk.Label(f, text="Configuration du scan", font=("Helvetica", 16, "bold"),
                 fg="#212f47").pack(anchor="w", pady=(0, 14))

        form = tk.Frame(f)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)

        tk.Label(form, text="URL du site").grid(row=0, column=0, sticky="w", pady=5)
        self.url_var = tk.StringVar()
        tk.Entry(form, textvariable=self.url_var).grid(
            row=0, column=1, columnspan=2, sticky="ew", padx=(8, 0))

        tk.Label(form, text="Token WPScan").grid(row=1, column=0, sticky="w", pady=5)
        self.token_var = tk.StringVar(value=self.cfg["token"])
        tk.Entry(form, textvariable=self.token_var, show="*").grid(
            row=1, column=1, sticky="ew", padx=(8, 8))
        self.remember_var = tk.BooleanVar(value=self.cfg["remember_token"])
        tk.Checkbutton(form, text="Memoriser", variable=self.remember_var).grid(
            row=1, column=2, sticky="w")

        tk.Label(form, text="Dossier du rapport").grid(
            row=2, column=0, sticky="w", pady=5)
        self.dir_var = tk.StringVar(value=self.cfg["output_dir"])
        tk.Entry(form, textvariable=self.dir_var).grid(
            row=2, column=1, sticky="ew", padx=(8, 8))
        tk.Button(form, text="Parcourir...", command=self._choose_dir).grid(
            row=2, column=2, sticky="ew")

        tk.Label(f, text="Le token est facultatif. Sans token, seul le test "
                         "Mozilla Observatory sera lance.",
                 fg="#777", justify="left").pack(anchor="w", pady=(12, 2))
        link = tk.Label(f, text="Obtenir un token gratuit sur wpscan.com/api",
                        fg="#1a6fc4", cursor="hand2")
        link.pack(anchor="w")
        link.bind("<Button-1>", lambda _e: _open_path("https://wpscan.com/api"))

        nav = tk.Frame(f)
        nav.pack(fill="x", pady=(24, 0))
        tk.Button(nav, text="<  Retour",
                  command=lambda: self.welcome.tkraise()).pack(side="left")
        tk.Button(nav, text="Lancer le scan  >", font=("Helvetica", 11, "bold"),
                  command=self._start_scan).pack(side="right")
        return f

    # --- Écran 3 : Progression --------------------------------------------
    def _build_progress(self) -> tk.Frame:
        f = tk.Frame(self.container, padx=26, pady=22)
        tk.Label(f, text="Scan en cours", font=("Helvetica", 16, "bold"),
                 fg="#212f47").pack(anchor="w", pady=(0, 12))

        self.steps = StepList(f)
        self.steps.pack(fill="x", pady=(0, 8))

        self.progress = ttk.Progressbar(f, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 8))

        self.status_label = tk.Label(f, text="", font=("Helvetica", 10, "bold"),
                                     justify="left", anchor="w")
        self.status_label.pack(fill="x")

        tk.Label(f, text="Journal", fg="#666").pack(anchor="w", pady=(8, 0))
        self.log_box = scrolledtext.ScrolledText(f, height=9, state="disabled")
        self.log_box.pack(fill="both", expand=True, pady=(0, 10))

        nav = tk.Frame(f)
        nav.pack(fill="x")
        self.new_btn = tk.Button(nav, text="Nouveau scan", command=self._reset,
                                 state="disabled")
        self.new_btn.pack(side="left")
        self.open_btn = tk.Button(nav, text="Ouvrir le rapport",
                                  command=self._open_report, state="disabled")
        self.open_btn.pack(side="right")
        return f

    # --- Actions interface -------------------------------------------------
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

    def _reset(self):
        if self.scanning:
            return
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")
        self.steps.reset()
        self.status_label.configure(text="")
        self.open_btn.configure(state="disabled")
        self.new_btn.configure(state="disabled")
        self.config_screen.tkraise()

    # --- Cycle de scan -----------------------------------------------------
    def _start_scan(self):
        if self.scanning:
            return
        url = _normalize_url(self.url_var.get())
        token = self.token_var.get().strip()
        out_dir = self.dir_var.get().strip()

        if not url:
            self._popup("Veuillez renseigner l'URL du site.")
            return
        if not os.path.isdir(out_dir):
            self._popup("Le dossier de destination est introuvable.")
            return

        config.save(token, out_dir, self.remember_var.get())
        self.url_var.set(url)

        self.scanning = True
        self.steps.reset()
        self.open_btn.configure(state="disabled")
        self.new_btn.configure(state="disabled")
        self.status_label.configure(text="Scan en cours...", fg="#1a6fc4")
        self.progress.start(12)
        self.progress_screen.tkraise()
        self._log(f"Cible : {url}")

        threading.Thread(target=self._worker, args=(token, url, out_dir),
                         daemon=True).start()

    def _popup(self, message: str):
        win = tk.Toplevel(self.root)
        win.title("Information")
        win.transient(self.root)
        tk.Label(win, text=message, padx=24, pady=18).pack()
        tk.Button(win, text="OK", command=win.destroy, width=10).pack(pady=(0, 14))

    def _worker(self, token, url, out_dir):
        """Exécuté dans un thread ; communique via la file, jamais via Tkinter."""
        log = lambda m: self.queue.put(("log", m))         # noqa: E731
        step = lambda i, s: self.queue.put(("step", i, s))  # noqa: E731
        wpscan_data = observatory_data = None
        errors = []

        # Étapes 0-1 : WPScan (uniquement si un token est fourni).
        if token:
            engine = None
            try:
                step(0, "running")
                engine = prepare(log)
                step(0, "done")
            except WPScanError as exc:
                step(0, "failed")
                errors.append(f"WPScan : {exc}")
            if engine:
                try:
                    step(1, "running")
                    wpscan_data = run_scan(engine, url, token, log)
                    step(1, "done")
                except WPScanError as exc:
                    step(1, "failed")
                    errors.append(f"WPScan : {exc}")
            else:
                step(1, "skipped")
        else:
            step(0, "skipped")
            step(1, "skipped")
            log("Aucun token WPScan : analyse WordPress ignoree.")

        # Étape 2 : Mozilla Observatory.
        try:
            step(2, "running")
            observatory_data = run_observatory(url, log)
            step(2, "done")
        except ObservatoryError as exc:
            step(2, "failed")
            errors.append(f"Observatory : {exc}")

        # Étape 3 : génération du PDF.
        try:
            step(3, "running")
            if wpscan_data is None and observatory_data is None:
                raise RuntimeError("Aucune source n'a produit de resultat.")
            path = generate_report(url, wpscan_data, observatory_data, out_dir)
            step(3, "done")
            self.queue.put(("done", path, errors))
        except Exception as exc:  # garde-fou : ne jamais bloquer l'UI
            step(3, "failed")
            self.queue.put(("error", str(exc)))

    def _drain_queue(self):
        try:
            while True:
                msg = self.queue.get_nowait()
                kind = msg[0]
                if kind == "log":
                    self._log(msg[1])
                elif kind == "step":
                    self.steps.set(msg[1], msg[2])
                elif kind == "done":
                    self._finish(ok=True, payload=msg[1], errors=msg[2])
                elif kind == "error":
                    self._finish(ok=False, payload=msg[1], errors=[])
        except queue.Empty:
            pass
        self.root.after(120, self._drain_queue)

    def _finish(self, ok: bool, payload: str, errors: list):
        self.scanning = False
        self.progress.stop()
        self.new_btn.configure(state="normal")
        if ok:
            self.last_report = payload
            self.open_btn.configure(state="normal")
            self._log(f"Rapport PDF genere : {payload}")
            if errors:
                self.status_label.configure(
                    text="Rapport genere (certaines sources ont echoue).",
                    fg="#c8781e")
                for e in errors:
                    self._log("Avertissement - " + e)
            else:
                self.status_label.configure(text="Scan termine avec succes.",
                                            fg="#277a47")
            _open_path(os.path.dirname(payload))
        else:
            self.status_label.configure(text="Echec : " + payload, fg="#c0392b")
            self._log("Erreur - " + payload)


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
