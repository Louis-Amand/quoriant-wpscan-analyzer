"""Transforme les résultats des sources (WPScan, Observatory) en PDF lisible."""

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from fpdf import FPDF, XPos, YPos

NAVY = (33, 47, 71)
RED = (192, 57, 43)
ORANGE = (200, 120, 30)
AMBER = (180, 140, 20)
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


def _count_all(data: dict) -> dict:
    core = len(_vulns(data.get("version")))
    theme = len(_vulns(data.get("main_theme")))
    plugins = sum(len(_vulns(p)) for p in (data.get("plugins") or {}).values())
    return {"core": core, "theme": theme, "plugins": plugins,
            "total": core + theme + plugins}


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
    pdf.cell(48, 6, _safe(key))
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(0, 0, 0)
    pdf.multi_cell(0, 6, _safe(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _body(pdf, text, color=(0, 0, 0), bold=False, size=10):
    pdf.set_font("Helvetica", "B" if bold else "", size)
    pdf.set_text_color(*color)
    pdf.multi_cell(0, 5.5, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _vuln_block(pdf, vuln):
    _body(pdf, "  - " + vuln.get("title", "Vulnerabilite"), color=RED, bold=True)
    fixed = vuln.get("fixed_in")
    pdf.set_x(pdf.l_margin + 6)
    _body(
        pdf,
        f"Corrigee dans la version : {fixed}" if fixed else "Aucun correctif connu",
        color=GREY, size=9,
    )
    refs = vuln.get("references") or {}
    for cve in (refs.get("cve") or [])[:4]:
        pdf.set_x(pdf.l_margin + 6)
        _body(pdf, f"CVE-{cve}", color=GREY, size=9)
    for url in (refs.get("url") or [])[:2]:
        pdf.set_x(pdf.l_margin + 6)
        _body(pdf, url, color=GREY, size=9)
    pdf.ln(1)


# --- Mozilla Observatory ---------------------------------------------------
def _grade_color(grade):
    g = (grade or "").upper()
    if g.startswith("A"):
        return GREEN
    if g.startswith("B"):
        return AMBER
    if g.startswith("C"):
        return ORANGE
    return RED


def _grade_comment(grade):
    g = (grade or "").upper()
    if g.startswith("A"):
        return "Excellente configuration des en-tetes de securite HTTP."
    if g.startswith("B"):
        return "Bonne configuration ; quelques en-tetes peuvent encore etre renforces."
    if g.startswith("C"):
        return "Configuration perfectible : plusieurs en-tetes de securite manquent."
    if g.startswith("D"):
        return "Configuration insuffisante : des en-tetes essentiels sont absents."
    return ("Configuration tres insuffisante : la majorite des en-tetes "
            "de securite sont absents.")


def _observatory_section(pdf, obs):
    _h1(pdf, "En-tetes HTTP - Mozilla Observatory")
    grade = obs.get("grade")
    color = _grade_color(grade)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*color)
    pdf.cell(0, 13, _safe(f"Note : {grade or 'N/A'}"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    if obs.get("score") is not None:
        _kv(pdf, "Score", f"{obs['score']}/100")
    passed, total = obs.get("tests_passed"), obs.get("tests_quantity")
    if passed is not None and total is not None:
        _kv(pdf, "Tests reussis", f"{passed} / {total}")
    if obs.get("tests_failed") is not None:
        _kv(pdf, "Tests echoues", str(obs["tests_failed"]))
    if obs.get("scanned_at"):
        _kv(pdf, "Analyse Mozilla", str(obs["scanned_at"]))
    pdf.ln(1)
    _body(pdf, _grade_comment(grade), bold=True, color=color)
    if obs.get("details_url"):
        _body(pdf, "Detail des tests : " + str(obs["details_url"]),
              color=GREY, size=9)


# --- WordPress / WPScan ----------------------------------------------------
def _wordpress_sections(pdf, data):
    _h1(pdf, "Coeur WordPress")
    core_vulns = _vulns(data.get("version"))
    if core_vulns:
        for v in core_vulns:
            _vuln_block(pdf, v)
    else:
        _body(pdf, "Aucune vulnerabilite connue pour cette version.", color=GREEN)

    _h1(pdf, "Theme actif")
    theme = data.get("main_theme") or {}
    if theme:
        _kv(pdf, "Theme", theme.get("style_name") or theme.get("slug") or "inconnu")
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

    plugins = data.get("plugins") or {}
    _h1(pdf, f"Extensions detectees ({len(plugins)})")
    if plugins:
        for slug, info in sorted(plugins.items()):
            info = info or {}
            pv = _vulns(info)
            line = f"{slug}  -  {_version_number(info) or 'version inconnue'}"
            if info.get("outdated"):
                line += "  (obsolete)"
            _body(pdf, line, bold=True, color=RED if pv else NAVY)
            if info.get("latest_version"):
                pdf.set_x(pdf.l_margin + 6)
                _body(pdf, f"Derniere version disponible : {info['latest_version']}",
                      color=GREY, size=9)
            for v in pv:
                _vuln_block(pdf, v)
            pdf.ln(1)
    else:
        _body(pdf, "Aucune extension detectee.", color=GREY)

    findings = data.get("interesting_findings") or []
    if findings:
        _h1(pdf, "Elements interessants")
        for f in findings:
            _body(pdf, "  - " + (f.get("to_s") or f.get("type") or "Information"),
                  bold=True, color=NAVY)
            if f.get("url"):
                pdf.set_x(pdf.l_margin + 6)
                _body(pdf, f["url"], color=GREY, size=9)
            pdf.ln(0.5)


def generate_report(target_url, wpscan, observatory, output_dir) -> str:
    """Écrit le PDF combiné dans `output_dir` et renvoie son chemin.

    `wpscan` et `observatory` peuvent valoir None (source non exécutée).
    """
    target = target_url
    if wpscan:
        target = wpscan.get("target_url") or wpscan.get("effective_url") or target_url

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
    if wpscan is not None:
        counts = _count_all(wpscan)
        total = counts["total"]
        pdf.set_fill_color(*(RED if total else GREEN))
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 12)
        msg = (f"{total} vulnerabilite(s) WordPress detectee(s)" if total
               else "Aucune vulnerabilite WordPress detectee")
        pdf.cell(0, 11, "   " + msg, new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        pdf.ln(1)
        _body(pdf, f"Coeur WordPress : {counts['core']}   |   "
                   f"Theme : {counts['theme']}   |   "
                   f"Extensions : {counts['plugins']}", color=GREY, size=9)
    else:
        pdf.set_fill_color(*NAVY)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 11, "   Analyse limitee aux en-tetes HTTP (aucun token WPScan)",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)

    # Informations générales
    _h1(pdf, "Informations generales")
    _kv(pdf, "URL cible", target)
    if observatory and observatory.get("grade"):
        _kv(pdf, "Note Observatory", observatory["grade"])
    if wpscan:
        if wpscan.get("target_ip"):
            _kv(pdf, "Adresse IP", wpscan["target_ip"])
        wp_version = _version_number(wpscan.get("version"))
        status = (wpscan.get("version") or {}).get("status")
        _kv(pdf, "Version WordPress",
            f"{wp_version or 'non identifiee'}" + (f" ({status})" if status else ""))
        if wpscan.get("elapsed") is not None:
            _kv(pdf, "Duree du scan WPScan", f"{wpscan['elapsed']} secondes")

    # Section Observatory
    if observatory:
        _observatory_section(pdf, observatory)
    else:
        _h1(pdf, "En-tetes HTTP - Mozilla Observatory")
        _body(pdf, "Test Observatory non effectue.", color=GREY)

    # Sections WordPress
    if wpscan:
        _wordpress_sections(pdf, wpscan)
    else:
        _h1(pdf, "Analyse WordPress (WPScan)")
        _body(pdf, "Analyse WordPress non effectuee : aucun token WPScan fourni.",
              color=GREY)
        _body(pdf, "Renseignez un token (gratuit sur wpscan.com/api) pour detecter "
                   "les vulnerabilites du coeur, du theme et des extensions.",
              color=GREY, size=9)

    host = re.sub(r"[^A-Za-z0-9]+", "-", urlparse(target).netloc or "site").strip("-")
    filename = f"wpscan_{host or 'site'}_{datetime.now():%Y%m%d-%H%M}.pdf"
    out_path = str(Path(output_dir) / filename)
    pdf.output(out_path)
    return out_path
