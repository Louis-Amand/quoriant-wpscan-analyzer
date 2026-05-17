#!/usr/bin/env python3
"""Construit l'exécutable autonome pour l'OS courant (via PyInstaller).

Le résultat est placé dans le dossier dist/ :
  • Windows : dist/WPScanAnalyzer.exe
  • macOS   : dist/WPScanAnalyzer.app
  • Linux   : dist/WPScanAnalyzer

Prérequis : pip install -r requirements.txt pyinstaller
Lancement : python build.py
"""

import subprocess
import sys

NAME = "WPScanAnalyzer"


def main() -> int:
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",            # pas de console derrière la fenêtre
        "--name", NAME,
        "--collect-all", "fpdf",      # polices internes de fpdf2
        "--collect-all", "certifi",   # magasin de certificats pour les appels HTTPS
        "run.py",
    ]
    print("Construction de l'exécutable :\n  " + " ".join(cmd) + "\n")
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print("PyInstaller introuvable. Installez-le : pip install pyinstaller")
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"Échec de la construction (code {exc.returncode}).")
        return exc.returncode
    print(f"\nTerminé. Exécutable disponible dans le dossier dist/ ({NAME}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
