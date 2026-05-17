"""Détection, installation et exécution de WPScan (Docker ou gem Ruby)."""

import json
import subprocess
import sys

DOCKER_IMAGE = "wpscanteam/wpscan"


class WPScanError(Exception):
    """Erreur fonctionnelle remontée à l'interface."""


def _run(cmd, timeout=None, check=False):
    """Lance une commande sans ouvrir de fenêtre console sous Windows."""
    kwargs = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
        "check": check,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    return subprocess.run(cmd, **kwargs)


def _exists(cmd):
    """Indique si une commande répond (binaire présent et fonctionnel)."""
    try:
        return _run(cmd, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _docker_ready():
    """Docker installé ET démon démarré."""
    return _exists(["docker", "info"])


def _docker_image_present():
    return _exists(["docker", "image", "inspect", DOCKER_IMAGE])


def prepare(log) -> str:
    """Garantit qu'un moteur WPScan est prêt. Renvoie 'docker' ou 'ruby'.

    `log` est une fonction recevant des lignes de texte pour l'interface.
    """
    # 1. Docker : solution privilégiée, identique sur tous les OS.
    if _docker_ready():
        log("Docker détecté.")
        if _docker_image_present():
            log("Image WPScan déjà présente.")
        else:
            log("Téléchargement de l'image WPScan (peut prendre 1-2 min)...")
            res = _run(["docker", "pull", DOCKER_IMAGE], timeout=900)
            if res.returncode != 0:
                raise WPScanError(
                    "Échec du téléchargement de l'image Docker WPScan.\n"
                    + (res.stderr or "")
                )
            log("Image WPScan téléchargée.")
        return "docker"

    log("Docker indisponible, bascule sur la version Ruby de WPScan.")

    # 2. WPScan déjà installé en tant que gem Ruby.
    if _exists(["wpscan", "--version"]):
        log("WPScan (gem Ruby) déjà installé.")
        return "ruby"

    # 3. Installation du gem si Ruby est présent.
    if not _exists(["gem", "--version"]):
        raise WPScanError(
            "Ni Docker ni Ruby ne sont disponibles sur cette machine.\n"
            "Installez l'un des deux puis relancez :\n"
            "  • Docker Desktop : https://www.docker.com/products/docker-desktop\n"
            "  • Ruby : https://www.ruby-lang.org/fr/documentation/installation/"
        )

    log("Installation de WPScan via 'gem install wpscan' (peut prendre quelques min)...")
    res = _run(["gem", "install", "wpscan"], timeout=900)
    if res.returncode != 0:
        # Nouvelle tentative en installation utilisateur (sans droits admin).
        log("Échec en mode global, tentative en installation utilisateur...")
        res = _run(["gem", "install", "--user-install", "wpscan"], timeout=900)
    if res.returncode != 0 or not _exists(["wpscan", "--version"]):
        raise WPScanError(
            "L'installation automatique de WPScan a échoué.\n"
            "Installez-le manuellement avec : gem install wpscan\n"
            + (res.stderr or "")
        )
    log("WPScan installé.")
    return "ruby"


def _scan_command(engine: str, url: str, token: str):
    base = ["--url", url, "--api-token", token, "--format", "json", "--no-banner"]
    if engine == "docker":
        return ["docker", "run", "--rm", DOCKER_IMAGE] + base
    return ["wpscan"] + base


def run_scan(engine: str, url: str, token: str, log) -> dict:
    """Exécute le scan et renvoie le rapport WPScan sous forme de dict."""
    log(f"Démarrage du scan de {url} ...")
    log("Cela peut durer plusieurs minutes selon le site.")
    try:
        res = _run(_scan_command(engine, url, token), timeout=3600)
    except subprocess.TimeoutExpired:
        raise WPScanError("Le scan a dépassé le délai maximal (1 h).")
    except OSError as exc:
        raise WPScanError(f"Impossible de lancer WPScan : {exc}")

    data = _parse_json(res.stdout)
    if data is None:
        raise WPScanError(
            "WPScan n'a pas renvoyé de résultat exploitable.\n"
            + (res.stderr or res.stdout or "Aucune sortie.")
        )
    if data.get("scan_aborted"):
        raise WPScanError(f"Scan interrompu par WPScan : {data['scan_aborted']}")
    log("Scan terminé, génération du rapport...")
    return data


def _parse_json(text: str):
    """Extrait le bloc JSON de la sortie WPScan, robuste aux lignes parasites."""
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    return None
