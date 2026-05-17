"""Sauvegarde/chargement des préférences (token, dossier de destination)."""

import json
import os
from pathlib import Path

CONFIG_DIR = Path.home() / ".wpscan-analyzer"
CONFIG_FILE = CONFIG_DIR / "config.json"


def desktop_path() -> str:
    """Renvoie le chemin du Bureau, ou le dossier personnel en repli."""
    desktop = Path.home() / "Desktop"
    if desktop.is_dir():
        return str(desktop)
    bureau = Path.home() / "Bureau"  # systèmes francophones
    if bureau.is_dir():
        return str(bureau)
    return str(Path.home())


def load() -> dict:
    """Charge la config ; renvoie des valeurs par défaut si absente/illisible."""
    defaults = {"token": "", "output_dir": desktop_path(), "remember_token": True}
    try:
        with open(CONFIG_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        defaults.update({k: v for k, v in data.items() if k in defaults})
    except (OSError, json.JSONDecodeError):
        pass
    return defaults


def save(token: str, output_dir: str, remember_token: bool) -> None:
    """Enregistre les préférences. Le token n'est gardé que si demandé."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    data = {
        "token": token if remember_token else "",
        "output_dir": output_dir,
        "remember_token": remember_token,
    }
    with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    try:
        os.chmod(CONFIG_FILE, 0o600)  # le token est sensible
    except OSError:
        pass
