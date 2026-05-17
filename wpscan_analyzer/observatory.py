"""Test Mozilla HTTP Observatory : note de sécurité des en-têtes HTTP.

API publique v2, sans token : https://developer.mozilla.org/observatory
"""

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse

import certifi

API = "https://observatory-api.mdn.mozilla.net/api/v2/scan"

# Magasin de certificats explicite : indispensable sous macOS et dans
# l'exécutable PyInstaller, où le magasin système n'est pas accessible.
_SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


class ObservatoryError(Exception):
    """Erreur fonctionnelle du test Observatory.

    `retryable` indique une panne transitoire (5xx, réseau) qui justifie
    une nouvelle tentative.
    """

    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


def _host(url: str) -> str:
    """Extrait le nom d'hôte d'une URL (Observatory attend un domaine)."""
    parsed = urlparse(url if "://" in url else "https://" + url)
    netloc = parsed.netloc or parsed.path
    return netloc.split("@")[-1].split(":")[0].strip("/")


def _http_error(exc: urllib.error.HTTPError) -> ObservatoryError:
    """Transforme une erreur HTTP Observatory en message exploitable.

    Observatory renvoie souvent un 500 dont le corps JSON explique la vraie
    cause (ex. site cible injoignable) : c'est un échec définitif, pas une
    panne à retenter.
    """
    detail = None
    error_code = None
    try:
        payload = json.loads(exc.read().decode("utf-8"))
        detail = payload.get("message")
        error_code = payload.get("error")
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        pass

    if error_code == "scan-failed":
        return ObservatoryError(
            "Le site cible n'a pas pu être analysé : il est injoignable ou "
            "renvoie une réponse invalide" + (f" ({detail})." if detail else "."),
            retryable=False)
    if detail:
        return ObservatoryError(f"Observatory : {detail}", retryable=False)
    # 5xx sans détail = panne serveur Mozilla, potentiellement transitoire.
    return ObservatoryError(f"Observatory a répondu {exc.code}.",
                            retryable=exc.code >= 500)


def _post(host: str) -> dict:
    """Envoie la requête de scan. Lève ObservatoryError en cas d'échec."""
    endpoint = f"{API}?host={urllib.parse.quote(host)}"
    req = urllib.request.Request(endpoint, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60, context=_SSL_CONTEXT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise _http_error(exc)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ObservatoryError(f"Connexion à Observatory impossible : {exc}",
                               retryable=True)
    except json.JSONDecodeError:
        raise ObservatoryError("Réponse Observatory illisible.")


def run_observatory(url: str, log) -> dict:
    """Lance le test Observatory et renvoie le résultat (avec note et score)."""
    host = _host(url)
    if not host:
        raise ObservatoryError("URL invalide pour le test Observatory.")
    log(f"Test Mozilla Observatory sur {host} ...")

    result: dict = {}
    last_error: ObservatoryError | None = None
    for attempt in range(10):
        try:
            result = _post(host)
        except ObservatoryError as exc:
            if not exc.retryable:
                raise
            last_error = exc
            log(f"Observatory momentanément indisponible, nouvelle tentative... "
                f"({exc})")
            time.sleep(6)
            continue

        if result.get("error"):
            raise ObservatoryError(
                f"Mozilla n'a pas pu analyser ce site : {result['error']}")
        if result.get("grade"):
            break
        log("Analyse en cours côté Mozilla, patientez...")
        time.sleep(6)

    if not result.get("grade"):
        if last_error is not None:
            raise ObservatoryError(
                "Le service Mozilla Observatory est momentanément indisponible "
                f"({last_error}). Réessayez le test plus tard.")
        raise ObservatoryError("Observatory n'a pas renvoyé de note à temps.")

    log(f"Observatory : note {result['grade']} ({result.get('score', '?')}/100).")
    return result
