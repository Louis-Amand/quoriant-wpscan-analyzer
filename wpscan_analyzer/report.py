"""Transforme le rapport JSON de WPScan en PDF lisible."""

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from fpdf import FPDF, XPos, YPos

NAVY = (33, 47, 71)
RED = (192, 57, 43)
GREEN = (39, 122, 71)
GREY = (110, 110, 110)
LIGHT = (238, 240, 243)


def _safe(text) -> str:
    """Rend un texte compatible avec les polices PDF de base (latin-1)."""
    return str(text).encode("latin-1", "replace").decode("latin-1")


def _vulns(node) -> list:
    """Liste de vulnérabilités d'un nœud WPScan, vide si absent."""
    if isinstance(node, dict):
        return node.get("vulnerabilities") or []
    return []


def _version_number(node):
    """Extrait le numéro de version (le champ peut être dict ou absent)."""
    if isinstance(node, dict):
        ver = node.get("version")
        if isinstance(ver, dict):
            return ver.get("number")
        if isinstance(ver, str):
            return ver
        return node.get("number")
    return None


class _Pdf(FPDF):
    def __init__(self, target: str):
        super().__init__()
        self.target = target
        self.set_auto_page_break(auto=True, margin=20)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*GREY)
        half = self.epw / 2
        self.cell(half, 10, _safe(self.target), align="L")
        self.cell(half, 10, f"Page {self.page_no()}/{{nb}}", align="R")


def _h1(pdf, text):
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*NAVY)
    pdf.set_fill_color(*LIGHT)
    pdf.cell(0, 9, _safe("  " + text), new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
    pdf.ln(2)


def _kv(pdf, key, value):
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*NAVY)
    pdf.cell(45, 6, _safe(key))
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(0, 0, 0)
    pdf.multi_cell(0, 6, _safe(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _body(pdf, text, color=(0, 0, 0), bold=False, size=10):
    pdf.set_font("Helvetica", "B" if bold else "", size)
    pdf.set_text_color(*color)
    pdf.multi_cell(0, 5.5, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _vuln_block(pdf, vuln):
    title = vuln.get("title", "Vulnérabilité")
    _body(pdf, "  • " + title, color=RED, bold=True)
    fixed = vuln.get("fixed_in")
    pdf.set_x(pdf.l_margin + 6)
    _body(
        pdf,
        f"Corrigée dans la version : {fixed}" if fixed else "Aucun correctif connu",
        color=GREY,
        size=9,
    )
    refs = vuln.get("references") or {}
    for cve in refs.get("cve", [])[:4]:
        pdf.set_x(pdf.l_margin + 6)
        _body(pdf, f"CVE-{cve}", color=GREY, size=9)
    for url in (refs.get("url") or [])[:2]:
        pdf.set_x(pdf.l_margin + 6)
        _body(pdf, url, color=GREY, size=9)
    pdf.ln(1)


def _count_all(data: dict) -> dict:
    core = len(_vulns(data.get("version")))
    theme = len(_vulns(data.get("main_theme")))
    plugins = sum(len(_vulns(p)) for p in (data.get("plugins") or {}).values())
    return {"core": core, "theme": theme, "plugins": plugins,
            "total": core + theme + plugins}


def generate_report(data: dict, output_dir: str) -> str:
    """Écrit le PDF dans `output_dir` et renvoie son chemin complet."""
    target = data.get("target_url") or data.get("effective_url") or "site inconnu"
    counts = _count_all(data)
    pdf = _Pdf(target)
    pdf.alias_nb_pages()
    pdf.add_page()

    # En-tête
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*NAVY)
    pdf.cell(0, 12, "Rapport de securite WordPress",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*GREY)
    pdf.cell(0, 7, _safe(target), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 7, "Genere le " + datetime.now().strftime("%d/%m/%Y a %H:%M"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Bandeau de synthèse
    pdf.ln(3)
    total = counts["total"]
    banner_color = RED if total else GREEN
    pdf.set_fill_color(*banner_color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 12)
    msg = (f"{total} vulnerabilite(s) detectee(s)" if total
           else "Aucune vulnerabilite detectee")
    pdf.cell(0, 11, "   " + msg, new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
    pdf.ln(1)
    _body(pdf, f"Coeur WordPress : {counts['core']}   |   "
               f"Theme : {counts['theme']}   |   "
               f"Extensions : {counts['plugins']}", color=GREY, size=9)

    # Informations générales
    _h1(pdf, "Informations generales")
    _kv(pdf, "URL cible", target)
    if data.get("target_ip"):
        _kv(pdf, "Adresse IP", data["target_ip"])
    if data.get("effective_url") and data["effective_url"] != target:
        _kv(pdf, "URL effective", data["effective_url"])
    wp_version = _version_number(data.get("version"))
    status = (data.get("version") or {}).get("status")
    _kv(pdf, "Version WordPress",
        f"{wp_version or 'non identifiee'}" + (f" ({status})" if status else ""))
    if data.get("elapsed") is not None:
        _kv(pdf, "Duree du scan", f"{data['elapsed']} secondes")
    if data.get("requests_done") is not None:
        _kv(pdf, "Requetes envoyees", str(data["requests_done"]))

    # Cœur WordPress
    _h1(pdf, "Coeur WordPress")
    core_vulns = _vulns(data.get("version"))
    if core_vulns:
        for v in core_vulns:
            _vuln_block(pdf, v)
    else:
        _body(pdf, "Aucune vulnerabilite connue pour cette version.", color=GREEN)

    # Thème
    _h1(pdf, "Theme actif")
    theme = data.get("main_theme") or {}
    if theme:
        name = theme.get("style_name") or theme.get("slug") or "inconnu"
        _kv(pdf, "Theme", name)
        _kv(pdf, "Version", str(_version_number(theme) or "inconnue"))
        if theme.get("latest_version"):
            _kv(pdf, "Derniere version", theme["latest_version"])
        if theme.get("outdated"):
            _body(pdf, "Ce theme n'est pas a jour.", color=RED, bold=True)
        theme_vulns = _vulns(theme)
        if theme_vulns:
            pdf.ln(1)
            for v in theme_vulns:
                _vuln_block(pdf, v)
        else:
            _body(pdf, "Aucune vulnerabilite connue pour ce theme.", color=GREEN)
    else:
        _body(pdf, "Aucun theme identifie.", color=GREY)

    # Extensions
    plugins = data.get("plugins") or {}
    _h1(pdf, f"Extensions detectees ({len(plugins)})")
    if plugins:
        for slug, info in sorted(plugins.items()):
            info = info or {}
            ver = _version_number(info) or "version inconnue"
            pv = _vulns(info)
            line = f"{slug}  -  {ver}"
            if info.get("outdated"):
                line += "  (obsolete)"
            _body(pdf, line, bold=True,
                  color=RED if pv else NAVY)
            if info.get("latest_version"):
                pdf.set_x(pdf.l_margin + 6)
                _body(pdf, f"Derniere version disponible : {info['latest_version']}",
                      color=GREY, size=9)
            for v in pv:
                _vuln_block(pdf, v)
            pdf.ln(1)
    else:
        _body(pdf, "Aucune extension detectee.", color=GREY)

    # Findings intéressants
    findings = data.get("interesting_findings") or []
    if findings:
        _h1(pdf, "Elements interessants")
        for f in findings:
            label = f.get("to_s") or f.get("type") or "Information"
            _body(pdf, "  • " + label, bold=True, color=NAVY)
            if f.get("url"):
                pdf.set_x(pdf.l_margin + 6)
                _body(pdf, f["url"], color=GREY, size=9)
            pdf.ln(0.5)

    host = re.sub(r"[^A-Za-z0-9]+", "-", urlparse(target).netloc or "site").strip("-")
    filename = f"wpscan_{host or 'site'}_{datetime.now():%Y%m%d-%H%M}.pdf"
    out_path = str(Path(output_dir) / filename)
    pdf.output(out_path)
    return out_path
