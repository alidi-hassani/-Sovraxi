"""Tkinter desktop interface for Sovraxi."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from sovraxi import Finding, scan_with_stats


BG = "#080f1b"
SIDEBAR = "#0b1524"
SURFACE = "#101c2d"
SURFACE_HI = "#15243a"
INPUT = "#0b1727"
TEXT = "#edf4fa"
MUTED = "#91a4b9"
DIM = "#60748d"
ACCENT = "#42e2b3"
ACCENT_DARK = "#10382f"
AMBER = "#f4bd61"
RED = "#ff7884"
STROKE = "#203148"
FONT = "Noto Sans"
MONO = "Noto Sans Mono"


class SovraxiApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Sovraxi — Code & App Auditor")
        self.root.geometry("1260x820")
        self.root.minsize(1020, 680)
        self.root.configure(bg=BG)
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.findings_by_iid: dict[str, Finding] = {}
        self.busy = False
        self._style()
        self._build()
        self.root.after(100, self._poll_events)
        self.root.after(350, self._show_guide)

    def _style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(
            "Sovraxi.Treeview", background=SURFACE, fieldbackground=SURFACE,
            foreground=TEXT, rowheight=42, borderwidth=0,
            font=(FONT, 10), relief="flat",
        )
        style.configure(
            "Sovraxi.Treeview.Heading", background=SURFACE_HI,
            foreground=MUTED, relief="flat", borderwidth=0,
            font=(FONT, 8, "bold"), padding=(12, 12),
        )
        style.map(
            "Sovraxi.Treeview", background=[("selected", "#1c3b3c")],
            foreground=[("selected", TEXT)],
        )
        style.configure(
            "Sovraxi.Vertical.TScrollbar", background=SURFACE_HI,
            troughcolor=SURFACE, bordercolor=SURFACE, arrowcolor=MUTED,
        )
        style.configure(
            "Sovraxi.Horizontal.TProgressbar", troughcolor=SURFACE_HI,
            background=ACCENT, bordercolor=SURFACE_HI,
            lightcolor=ACCENT, darkcolor=ACCENT,
        )

    def _build(self) -> None:
        shell = tk.Frame(self.root, bg=BG)
        shell.pack(fill="both", expand=True)
        self._build_sidebar(shell)

        self.main = tk.Frame(shell, bg=BG, padx=36, pady=27)
        self.main.pack(side="left", fill="both", expand=True)
        self._build_topbar()
        self._build_heading()
        self._build_scan_card()
        self._build_stats()
        self._build_results()

    def _build_sidebar(self, parent: tk.Widget) -> None:
        sidebar = tk.Frame(parent, bg=SIDEBAR, width=236,
                           highlightthickness=1, highlightbackground=STROKE)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        brand = tk.Frame(sidebar, bg=SIDEBAR, padx=22, pady=27)
        brand.pack(fill="x")
        mark = tk.Canvas(brand, width=38, height=38, bg=SIDEBAR,
                         highlightthickness=0)
        mark.pack(side="left", padx=(0, 11))
        mark.create_oval(1, 1, 37, 37, fill=ACCENT_DARK, outline="")
        mark.create_text(19, 19, text="S", fill=ACCENT,
                         font=(FONT, 18, "bold"))
        wordmark = tk.Frame(brand, bg=SIDEBAR)
        wordmark.pack(side="left", anchor="center")
        tk.Label(wordmark, text="sovraxi", bg=SIDEBAR, fg=TEXT,
                 font=(FONT, 16, "bold")).pack(anchor="w")
        tk.Label(wordmark, text="CODE & APP AUDITOR", bg=SIDEBAR, fg=DIM,
                 font=(FONT, 7, "bold")).pack(anchor="w", pady=(1, 0))

        tk.Frame(sidebar, bg=STROKE, height=1).pack(fill="x", padx=20, pady=(0, 25))
        tk.Label(sidebar, text="ESPACE DE TRAVAIL", bg=SIDEBAR, fg=DIM,
                 font=(FONT, 8, "bold")).pack(anchor="w", padx=22, pady=(0, 10))
        nav = tk.Frame(sidebar, bg=ACCENT_DARK, padx=12, pady=11)
        nav.pack(fill="x", padx=14)
        tk.Frame(nav, bg=ACCENT, width=3, height=20).pack(side="left", padx=(0, 10))
        tk.Label(nav, text="⌕", bg=ACCENT_DARK, fg=ACCENT,
                 font=(FONT, 17, "bold")).pack(side="left", padx=(0, 7))
        tk.Label(nav, text="Scanner", bg=ACCENT_DARK, fg=TEXT,
                 font=(FONT, 10, "bold")).pack(side="left")

        tk.Label(sidebar, text="ANALYSES INCLUSES", bg=SIDEBAR, fg=DIM,
                 font=(FONT, 8, "bold")).pack(anchor="w", padx=22, pady=(30, 12))
        for short, title, sub in (
            ("KEY", "Secrets exposés", "Code source et chaînes binaires"),
            ("SRC", "Code source", "Python, JS/TS, Java, Go, C/C++…"),
            ("APK", "Applications", "APK et archives ZIP compatibles"),
            ("BIN", "Binaires", "ELF / PE · chaînes et protections"),
        ):
            self._rule_item(sidebar, short, title, sub)

        spacer = tk.Frame(sidebar, bg=SIDEBAR)
        spacer.pack(fill="both", expand=True)
        privacy = tk.Frame(sidebar, bg="#10251f", padx=14, pady=14,
                           highlightthickness=1, highlightbackground="#1b453b")
        privacy.pack(fill="x", padx=14, pady=(0, 17))
        tk.Label(privacy, text="●  LOCAL PAR DESIGN", bg="#10251f", fg=ACCENT,
                 font=(FONT, 8, "bold")).pack(anchor="w")
        tk.Label(privacy, text="Tes fichiers restent sur\nta machine. Aucun envoi.",
                 bg="#10251f", fg="#a7c4b9", justify="left",
                 font=(FONT, 9), pady=8).pack(anchor="w")
        tk.Label(sidebar, text="VERSION 0.2 · OPEN SOURCE", bg=SIDEBAR, fg=DIM,
                 font=(FONT, 7, "bold")).pack(anchor="w", padx=21, pady=(0, 17))

    def _rule_item(self, parent: tk.Widget, short: str, title: str, sub: str) -> None:
        row = tk.Frame(parent, bg=SIDEBAR, padx=22, pady=8)
        row.pack(fill="x")
        badge = tk.Label(row, text=short, bg=SURFACE_HI, fg="#b8c8da",
                         width=4, pady=5, font=(MONO, 7, "bold"))
        badge.pack(side="left", padx=(0, 10))
        labels = tk.Frame(row, bg=SIDEBAR)
        labels.pack(side="left", fill="x")
        tk.Label(labels, text=title, bg=SIDEBAR, fg=TEXT,
                 font=(FONT, 9, "bold")).pack(anchor="w")
        tk.Label(labels, text=sub, bg=SIDEBAR, fg=DIM,
                 font=(FONT, 7)).pack(anchor="w", pady=(2, 0))

    def _build_topbar(self) -> None:
        bar = tk.Frame(self.main, bg=BG)
        bar.pack(fill="x", pady=(0, 27))
        tk.Label(bar, text="ESPACE DE TRAVAIL   /   SCANNER", bg=BG, fg=MUTED,
                 font=(FONT, 8, "bold")).pack(side="left")
        guide_button = tk.Button(
            bar, text="?  Guide rapide", command=self._show_guide,
            bg=SURFACE_HI, fg=TEXT, activebackground="#203450",
            activeforeground=TEXT, relief="flat", padx=12, pady=7,
            font=(FONT, 8, "bold"), cursor="hand2", borderwidth=0,
        )
        guide_button.pack(side="right", padx=(8, 0))
        self.connection_badge = tk.Label(bar, text="●  100 % LOCAL", bg="#10251f",
                                         fg=ACCENT, padx=11, pady=7,
                                         font=(FONT, 8, "bold"))
        self.connection_badge.pack(side="right")

    def _build_heading(self) -> None:
        heading = tk.Frame(self.main, bg=BG)
        heading.pack(fill="x", pady=(0, 22))
        tk.Label(heading, text="Repère les risques\navant de publier.", bg=BG, fg=TEXT,
                 justify="left", font=(FONT, 25, "bold"),
                 pady=2).pack(side="left", anchor="w")
        tk.Label(heading,
                 text="Analyse un dépôt avant de le partager.\nLes détections restent sur cet ordinateur.",
                 bg=BG, fg=MUTED, justify="right", font=(FONT, 10),
                 pady=7).pack(side="right", anchor="e", pady=(8, 0))

    def _build_scan_card(self) -> None:
        card = tk.Frame(self.main, bg=SURFACE, padx=20, pady=18,
                        highlightthickness=1, highlightbackground=STROKE)
        card.pack(fill="x", pady=(0, 17))

        title_row = tk.Frame(card, bg=SURFACE)
        title_row.pack(fill="x", pady=(0, 13))
        tk.Label(title_row, text="01", bg=ACCENT_DARK, fg=ACCENT,
                 padx=8, pady=4, font=(MONO, 8, "bold")).pack(side="left", padx=(0, 9))
        tk.Label(title_row, text="Choisis un dépôt à analyser", bg=SURFACE, fg=TEXT,
                 font=(FONT, 11, "bold")).pack(side="left")
        tk.Label(title_row, text="SCAN LOCAL · SANS TÉLÉVERSEMENT", bg=SURFACE,
                 fg=DIM, font=(FONT, 7, "bold")).pack(side="right")

        controls = tk.Frame(card, bg=SURFACE)
        controls.pack(fill="x")
        self.path_var = tk.StringVar(value="")
        entry_shell = tk.Frame(controls, bg=INPUT, highlightthickness=1,
                               highlightbackground=STROKE)
        entry_shell.pack(side="left", fill="x", expand=True, padx=(0, 9))
        tk.Label(entry_shell, text="⌂", bg=INPUT, fg=ACCENT,
                 font=(FONT, 14, "bold")).pack(side="left", padx=(12, 8))
        self.path_entry = tk.Entry(entry_shell, textvariable=self.path_var,
                                   bg=INPUT, fg=TEXT, insertbackground=ACCENT,
                                   selectbackground=ACCENT_DARK, relief="flat",
                                   font=(MONO, 9), borderwidth=0)
        self.path_entry.pack(side="left", fill="x", expand=True, ipady=12, padx=(0, 9))
        self.browse_button = tk.Button(
            controls, text="Parcourir", command=self._browse,
            bg=SURFACE_HI, fg=TEXT, activebackground="#203450",
            activeforeground=TEXT, relief="flat", padx=16, pady=10,
            font=(FONT, 9, "bold"), cursor="hand2", borderwidth=0,
        )
        self.browse_button.pack(side="left", padx=(0, 9))
        self.scan_button = tk.Button(
            controls, text="Lancer le scan  →", command=self._start_scan,
            bg=ACCENT, fg="#09251f", activebackground="#71efc9",
            activeforeground="#09251f", relief="flat", padx=18, pady=10,
            font=(FONT, 9, "bold"), cursor="hand2", borderwidth=0,
        )
        self.scan_button.pack(side="left")

        status_row = tk.Frame(card, bg=SURFACE)
        status_row.pack(fill="x", pady=(13, 0))
        self.progress = ttk.Progressbar(status_row, style="Sovraxi.Horizontal.TProgressbar",
                                        mode="indeterminate", length=92)
        self.progress.pack(side="left", padx=(0, 10))
        self.status_var = tk.StringVar(value="En attente de lancement")
        tk.Label(status_row, textvariable=self.status_var, bg=SURFACE, fg=MUTED,
                 font=(FONT, 8)).pack(side="left")
        self.status_right = tk.Label(status_row, text="Source · APK/ZIP · ELF/PE · local",
                                     bg=SURFACE, fg=DIM, font=(FONT, 8))
        self.status_right.pack(side="right")

    def _build_stats(self) -> None:
        row = tk.Frame(self.main, bg=BG)
        row.pack(fill="x", pady=(0, 17))
        self.finding_value = self._stat_card(row, "DÉTECTIONS", "—", "Risques potentiels", ACCENT)
        self.files_value = self._stat_card(row, "FICHIERS ANALYSÉS", "—", "Fichiers parcourus", TEXT)
        self.state_value = self._stat_card(row, "ÉTAT", "EN ATTENTE", "Dernière analyse", AMBER)

    def _stat_card(self, parent: tk.Widget, eyebrow: str, value: str,
                   caption: str, accent: str) -> tk.Label:
        card = tk.Frame(parent, bg=SURFACE, padx=17, pady=14,
                        highlightthickness=1, highlightbackground=STROKE)
        card.pack(side="left", fill="both", expand=True, padx=(0, 10))
        top = tk.Frame(card, bg=SURFACE)
        top.pack(fill="x")
        tk.Label(top, text=eyebrow, bg=SURFACE, fg=MUTED,
                 font=(FONT, 8, "bold")).pack(side="left")
        tk.Label(top, text="●", bg=SURFACE, fg=accent,
                 font=(FONT, 8)).pack(side="right")
        value_label = tk.Label(card, text=value, bg=SURFACE, fg=accent,
                               font=(FONT, 20, "bold"))
        value_label.pack(anchor="w", pady=(8, 1))
        tk.Label(card, text=caption, bg=SURFACE, fg=DIM,
                 font=(FONT, 8)).pack(anchor="w")
        return value_label

    def _build_results(self) -> None:
        panel = tk.Frame(self.main, bg=SURFACE, highlightthickness=1,
                         highlightbackground=STROKE)
        panel.pack(fill="both", expand=True)
        heading = tk.Frame(panel, bg=SURFACE, padx=17, pady=14)
        heading.pack(fill="x")
        labels = tk.Frame(heading, bg=SURFACE)
        labels.pack(side="left")
        tk.Label(labels, text="Détections", bg=SURFACE, fg=TEXT,
                 font=(FONT, 12, "bold")).pack(anchor="w")
        tk.Label(labels, text="Double-clique une alerte pour comprendre le risque et la correction.",
                 bg=SURFACE, fg=MUTED, font=(FONT, 8)).pack(anchor="w", pady=(3, 0))
        self.result_count = tk.Label(heading, text="AUCUN RÉSULTAT", bg=SURFACE_HI,
                                    fg=MUTED, padx=9, pady=5,
                                    font=(FONT, 7, "bold"))
        self.result_count.pack(side="right", anchor="n")
        tk.Frame(panel, bg=STROKE, height=1).pack(fill="x")

        body = tk.Frame(panel, bg=SURFACE)
        body.pack(fill="both", expand=True, padx=10, pady=10)
        columns = ("severity", "kind", "file", "line", "value")
        self.table = ttk.Treeview(body, columns=columns, show="headings",
                                  style="Sovraxi.Treeview")
        specs = (
            ("severity", "GRAVITÉ", 95, False),
            ("kind", "DÉTECTION", 220, False),
            ("file", "EMPLACEMENT", 360, True),
            ("line", "POSITION", 105, False),
            ("value", "VALEUR DÉTECTÉE", 240, False),
        )
        for name, label, width, stretch in specs:
            self.table.heading(name, text=label)
            self.table.column(name, width=width, minwidth=65,
                              anchor="w", stretch=stretch)
        scroll = ttk.Scrollbar(body, orient="vertical", command=self.table.yview,
                               style="Sovraxi.Vertical.TScrollbar")
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.table.tag_configure("even", background=SURFACE)
        self.table.tag_configure("odd", background="#122033")
        self.table.tag_configure("risk", foreground=AMBER)
        self.table.tag_configure("critical", foreground=RED)
        self.table.bind("<Double-1>", self._show_finding_detail)
        self._show_empty()

    def _browse(self) -> None:
        current = Path(self.path_var.get()).expanduser()
        initialdir = current if current.is_dir() else Path.home()
        selected = filedialog.askdirectory(
            parent=self.root, initialdir=str(initialdir),
            title="Choisir le dossier du dépôt à analyser",
        )
        if selected:
            self.path_var.set(selected)
            self.status_var.set(f"Dossier sélectionné : {selected}")

    def _start_scan(self) -> None:
        if self.busy:
            return
        raw_path = self.path_var.get().strip()
        if not raw_path:
            messagebox.showinfo(
                "Choisis un dossier", "Sélectionne d’abord le dossier de ton projet.",
                parent=self.root,
            )
            return
        path = Path(raw_path).expanduser()
        if not path.exists():
            self.status_var.set("Dossier introuvable. Vérifie le chemin ou utilise Parcourir.")
            self.path_entry.focus_set()
            messagebox.showerror(
                "Dossier introuvable",
                f"Ce chemin n’existe pas :\n{path}\n\nClique sur « Parcourir » et sélectionne le dossier réel de ton projet.",
                parent=self.root,
            )
            return
        if not path.is_dir():
            self.status_var.set("Le chemin choisi est un fichier ; sélectionne le dossier du projet.")
            messagebox.showerror(
                "Un dossier est nécessaire",
                "Sélectionne le dossier qui contient ton projet, pas un fichier précis.",
                parent=self.root,
            )
            return
        self.busy = True
        self.finding_value.configure(text="—")
        self.files_value.configure(text="—")
        self.state_value.configure(text="EN COURS", fg=AMBER)
        self.result_count.configure(text="SCAN EN COURS", bg=SURFACE_HI, fg=MUTED)
        self._show_empty("Analyse en cours…", f"Dossier : {path}")
        self.scan_button.configure(state="disabled", text="Analyse en cours…")
        self.browse_button.configure(state="disabled")
        self.progress.start(12)
        self.status_var.set(f"Analyse de {path}…")
        self.status_right.configure(text="Parcours local des fichiers…")
        threading.Thread(target=self._scan_worker, args=(path,), daemon=True).start()

    def _scan_worker(self, path: Path) -> None:
        try:
            self.events.put(("done", scan_with_stats(path)))
        except Exception as exc:  # surfaced in the UI; file contents are not included
            self.events.put(("error", str(exc)))

    def _poll_events(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                self._finish_scan(kind, payload)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_events)

    def _finish_scan(self, kind: str, payload: object) -> None:
        self.busy = False
        self.progress.stop()
        self.scan_button.configure(state="normal", text="Lancer le scan  →")
        self.browse_button.configure(state="normal")
        if kind == "error":
            self.state_value.configure(text="ERREUR", fg=RED)
            self.status_var.set("Le scan n’a pas pu aboutir")
            self.root.bell()
            messagebox.showerror("Échec du scan", str(payload), parent=self.root)
            return

        findings = payload
        assert isinstance(findings, tuple) and len(findings) == 2
        findings, scanned_files = findings
        assert isinstance(findings, list) and isinstance(scanned_files, int)
        self.finding_value.configure(text=str(len(findings)))
        self.files_value.configure(text=str(scanned_files))
        self.status_right.configure(text=f"{scanned_files} fichier(s) parcouru(s) · local")
        self.root.bell()
        if findings:
            self.state_value.configure(text="À VÉRIFIER", fg=AMBER)
            self.status_var.set(f"Analyse terminée : {len(findings)} alerte(s). Double-clique pour voir le détail et la correction.")
            self.result_count.configure(text=f"{len(findings)} DÉTECTION(S)",
                                        bg="#392d1d", fg=AMBER)
            self._populate(findings)
        else:
            self.state_value.configure(text="SANS ALERTE", fg=ACCENT)
            if scanned_files:
                self.status_var.set(f"Terminé : {scanned_files} fichier(s) parcouru(s), aucun motif connu détecté.")
                empty_title = "Aucun motif détecté"
                empty_message = f"{scanned_files} fichier(s) parcouru(s). Les règles actuelles n’ont relevé aucun motif connu. Cela ne garantit pas l’absence de vulnérabilité."
            else:
                self.status_var.set("Analyse terminée, mais aucun fichier régulier n’a été parcouru dans ce dossier.")
                empty_title = "Aucun fichier parcouru"
                empty_message = "Vérifie que le dossier choisi contient bien les fichiers du projet."
            self.result_count.configure(text="0 DÉTECTION", bg=ACCENT_DARK, fg=ACCENT)
            self._show_empty(empty_title, empty_message)

    def _populate(self, findings: list[Finding]) -> None:
        self.table.delete(*self.table.get_children())
        self.findings_by_iid.clear()
        for index, item in enumerate(findings):
            iid = self.table.insert(
                "", "end",
                values=(item.severity, item.rule, item.path,
                        f"{item.location_type} {item.line}",
                        item.secret_value or "—"),
                tags=("even" if index % 2 == 0 else "odd",
                      "critical" if item.severity in {"Critique", "Bloquante"} else "risk"),
            )
            self.findings_by_iid[iid] = item

    def _show_finding_detail(self, _event: tk.Event) -> None:
        selection = self.table.selection()
        if not selection:
            return
        finding = self.findings_by_iid.get(selection[0])
        if finding is None:
            return

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Détail — {finding.rule}")
        dialog.configure(bg=BG)
        dialog.geometry("700x620")
        dialog.minsize(600, 520)
        dialog.transient(self.root)
        dialog.grab_set()

        body = tk.Frame(dialog, bg=BG, padx=28, pady=24)
        body.pack(fill="both", expand=True)
        top = tk.Frame(body, bg=BG)
        top.pack(fill="x", pady=(0, 18))
        severity_color = RED if finding.severity in {"Critique", "Bloquante"} else AMBER
        tk.Label(top, text=finding.category.upper(), bg=BG, fg=ACCENT,
                 font=(FONT, 8, "bold")).pack(side="left")
        tk.Label(top, text=finding.severity.upper(), bg="#392d1d", fg=severity_color,
                 padx=10, pady=5, font=(FONT, 8, "bold")).pack(side="right")
        tk.Label(body, text=finding.rule, bg=BG, fg=TEXT,
                 font=(FONT, 20, "bold"), wraplength=640,
                 justify="left").pack(anchor="w")
        tk.Label(body, text=f"{finding.path}  ·  {finding.location_type} {finding.line}",
                 bg=BG, fg=MUTED, font=(MONO, 9),
                 wraplength=640, justify="left").pack(anchor="w", pady=(7, 16))

        self._detail_section(body, "POURQUOI CETTE ALERTE", finding.explanation)
        self._detail_section(body, "RISQUE POSSIBLE", finding.impact)
        self._detail_section(body, "COMMENT CORRIGER", finding.fix, accent=ACCENT)
        if finding.secret_value:
            self._secret_section(body, finding.secret_value)

        tk.Label(body, text="Analyse heuristique : vérifie le contexte avant de conclure qu’il s’agit d’une vulnérabilité.",
                 bg=BG, fg=DIM, font=(FONT, 8), wraplength=640,
                 justify="left").pack(anchor="w", side="bottom", pady=(14, 0))

    @staticmethod
    def _detail_section(parent: tk.Widget, heading: str, detail: str,
                        accent: str = MUTED) -> None:
        panel = tk.Frame(parent, bg=SURFACE, padx=14, pady=11,
                         highlightthickness=1, highlightbackground=STROKE)
        panel.pack(fill="x", pady=(0, 8))
        tk.Label(panel, text=heading, bg=SURFACE, fg=accent,
                 font=(FONT, 8, "bold")).pack(anchor="w")
        tk.Label(panel, text=detail, bg=SURFACE, fg=TEXT,
                 font=(FONT, 9), justify="left", wraplength=600,
                 pady=5).pack(anchor="w")

    def _secret_section(self, parent: tk.Widget, secret: str) -> None:
        panel = tk.Frame(parent, bg=SURFACE, padx=14, pady=11,
                         highlightthickness=1, highlightbackground=STROKE)
        panel.pack(fill="x", pady=(0, 8))
        tk.Label(panel, text="SECRET DÉTECTÉ · AFFICHÉ EN CLAIR SUR CET APPAREIL",
                 bg=SURFACE, fg=AMBER, font=(FONT, 8, "bold")).pack(anchor="w")
        row = tk.Frame(panel, bg=SURFACE)
        row.pack(fill="x", pady=(7, 0))
        value = tk.Entry(row, bg=INPUT, fg=TEXT, insertbackground=TEXT,
                         readonlybackground=INPUT, relief="flat",
                         font=(MONO, 9), borderwidth=0)
        value.insert(0, secret)
        value.configure(state="readonly")
        value.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 8))
        tk.Button(
            row, text="Copier", command=lambda: self._copy_secret(secret),
            bg=SURFACE_HI, fg=TEXT, activebackground="#203450",
            activeforeground=TEXT, relief="flat", padx=12, pady=7,
            font=(FONT, 8, "bold"), cursor="hand2", borderwidth=0,
        ).pack(side="right")

    def _copy_secret(self, secret: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(secret)
        self.root.update_idletasks()

    def _show_empty(self, title: str = "Prêt pour le premier scan",
                    subtitle: str = "Choisis un dépôt ci-dessus pour rechercher des secrets.") -> None:
        self.table.delete(*self.table.get_children())
        self.table.insert("", "end", values=("", title, subtitle, "", ""), tags=("even",))

    def _show_guide(self) -> None:
        if getattr(self, "guide_window", None) is not None:
            try:
                if self.guide_window.winfo_exists():
                    self.guide_window.lift()
                    return
            except tk.TclError:
                pass

        dialog = tk.Toplevel(self.root)
        self.guide_window = dialog
        dialog.title("Guide de démarrage — Sovraxi")
        dialog.configure(bg=BG)
        dialog.resizable(False, False)
        dialog.transient(self.root)
        width, height = 600, 570
        self.root.update_idletasks()
        x = self.root.winfo_rootx() + max(0, (self.root.winfo_width() - width) // 2)
        y = self.root.winfo_rooty() + max(0, (self.root.winfo_height() - height) // 2)
        dialog.geometry(f"{width}x{height}+{x}+{y}")

        body = tk.Frame(dialog, bg=BG, padx=30, pady=26)
        body.pack(fill="both", expand=True)
        eyebrow = tk.Frame(body, bg=BG)
        eyebrow.pack(fill="x", pady=(0, 14))
        tk.Label(eyebrow, text="SOVRAXI  /  GUIDE DE DÉMARRAGE", bg=BG,
                 fg=ACCENT, font=(FONT, 8, "bold")).pack(side="left")
        tk.Label(body, text="Ton premier scan,\nen trois étapes.", bg=BG,
                 fg=TEXT, justify="left", font=(FONT, 23, "bold")).pack(anchor="w")
        tk.Label(body,
                 text="Sovraxi recherche des secrets et des motifs de code à risque.\nTout reste sur ton ordinateur.",
                 bg=BG, fg=MUTED, justify="left", font=(FONT, 9),
                 pady=10).pack(anchor="w")

        steps = (
            ("01", "Sélectionne ton dépôt", "Choisis le dossier local du projet à vérifier."),
            ("02", "Lance l’analyse", "Sovraxi parcourt les fichiers et ignore les dépendances courantes et le dossier .git."),
            ("03", "Ouvre une alerte", "Double-clique dessus pour comprendre la détection, le risque et la correction conseillée."),
        )
        for number, title, description in steps:
            row = tk.Frame(body, bg=SURFACE, padx=13, pady=11,
                           highlightthickness=1, highlightbackground=STROKE)
            row.pack(fill="x", pady=(0, 7))
            tk.Label(row, text=number, bg=ACCENT_DARK, fg=ACCENT,
                     padx=8, pady=7, font=(MONO, 9, "bold")).pack(side="left", padx=(0, 12))
            copy = tk.Frame(row, bg=SURFACE)
            copy.pack(side="left", fill="x", expand=True)
            tk.Label(copy, text=title, bg=SURFACE, fg=TEXT,
                     font=(FONT, 9, "bold")).pack(anchor="w")
            tk.Label(copy, text=description, bg=SURFACE, fg=MUTED,
                     font=(FONT, 8), wraplength=430, justify="left").pack(anchor="w", pady=(3, 0))

        note = tk.Frame(body, bg="#10251f", padx=13, pady=10,
                        highlightthickness=1, highlightbackground="#1b453b")
        note.pack(fill="x", pady=(6, 0))
        tk.Label(note, text="SECRET CONFIRMÉ ?", bg="#10251f", fg=ACCENT,
                 font=(FONT, 8, "bold")).pack(anchor="w")
        tk.Label(note, text="Révoque-le ou renouvelle-le immédiatement. Supprimer le fichier ne rend pas un secret exposé inutilisable.",
                 bg="#10251f", fg="#a7c4b9", font=(FONT, 8),
                 wraplength=500, justify="left").pack(anchor="w", pady=(4, 0))

        actions = tk.Frame(body, bg=BG)
        actions.pack(fill="x", side="bottom", pady=(14, 0))
        tk.Button(actions, text="Plus tard", command=dialog.destroy,
                  bg=BG, fg=MUTED, activebackground=BG, activeforeground=TEXT,
                  relief="flat", padx=15, pady=10, font=(FONT, 9),
                  cursor="hand2", borderwidth=0).pack(side="right")
        tk.Button(actions, text="Choisir un dépôt  →",
                  command=lambda: self._guide_choose(dialog),
                  bg=ACCENT, fg="#09251f", activebackground="#71efc9",
                  activeforeground="#09251f", relief="flat", padx=17, pady=10,
                  font=(FONT, 9, "bold"), cursor="hand2", borderwidth=0).pack(side="right", padx=(0, 8))
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.grab_set()
        dialog.focus_set()

    def _guide_choose(self, dialog: tk.Toplevel) -> None:
        selected = filedialog.askdirectory(parent=dialog, title="Choisir le dossier du dépôt")
        if not selected:
            return
        self.path_var.set(selected)
        dialog.destroy()
        self._start_scan()


def launch() -> None:
    root = tk.Tk()
    SovraxiApp(root)
    root.mainloop()


if __name__ == "__main__":
    launch()
