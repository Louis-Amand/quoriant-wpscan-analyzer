# WPScan Analyzer

Outil graphique tout-en-un pour analyser la sécurité d'un site WordPress et
produire un **rapport PDF** clair, sans connaître la ligne de commande.

Le rapport combine plusieurs sources :

- **[WPScan](https://wpscan.com/)** — vulnérabilités du cœur WordPress, du thème
  et des extensions ;
- **[Mozilla HTTP Observatory](https://developer.mozilla.org/observatory)** —
  note de sécurité des en-têtes HTTP du site (A+ à F).

Pensé pour les personnes qui gèrent des sites WordPress sous **Windows, macOS
ou Linux** : on saisit l'URL du site, on clique, on récupère un PDF.

## ⚠️ Avertissement légal

Scanner un site web sans autorisation est **illégal** dans la plupart des pays.
N'utilisez cet outil que sur :

- des sites que vous **possédez** ;
- des sites pour lesquels vous disposez d'une **autorisation écrite** du
  propriétaire (par exemple un mandat de maintenance ou de test).

L'auteur et les contributeurs déclinent toute responsabilité en cas d'usage
abusif. Vous êtes seul responsable de l'utilisation que vous faites de WPScan
Analyzer.

## Fonctionnement

L'interface se déroule en **3 écrans** :

1. **Accueil** — présente les sources utilisées dans le rapport.
2. **Configuration** — URL du site, token WPScan (facultatif), dossier de
   destination (le **Bureau** par défaut).
3. **Progression** — chaque étape s'affiche avec sa case d'état (préparation,
   scan WordPress, test Observatory, génération du PDF).

En coulisses :

- **Installation automatique de WPScan** *(uniquement si absent)* : via
  **Docker** (image `wpscanteam/wpscan`) s'il est disponible, sinon via le
  **gem Ruby** `wpscan`.
- **Le test Observatory ne nécessite aucun token** ni installation.
- **Token WPScan facultatif** : sans token, seul le test Observatory est
  effectué. Le token peut être mémorisé pour ne pas le ressaisir
  (stocké dans `~/.wpscan-analyzer/config.json`, accès restreint au compte).
- **Rapport PDF** généré dans le dossier choisi, même si une source échoue
  (le rapport contient alors les résultats disponibles).

## Obtenir un token WPScan

Gratuit (25 requêtes/jour) sur <https://wpscan.com/api>.

## Utilisation rapide (avec Python installé)

```bash
pip install -r requirements.txt
python run.py
```

## Créer un exécutable autonome (pour distribution)

Pour fournir un fichier à double-cliquer, sans rien installer côté
utilisateur. À lancer **sur chaque OS visé** :

```bash
pip install -r requirements.txt pyinstaller
python build.py
```

L'exécutable est généré dans `dist/` :

| OS      | Fichier produit               |
|---------|--------------------------------|
| Windows | `dist/WPScanAnalyzer.exe`      |
| macOS   | `dist/WPScanAnalyzer.app`      |
| Linux   | `dist/WPScanAnalyzer`          |

> **macOS — première ouverture.** L'exécutable n'est pas signé par un compte
> développeur Apple payant. Au premier lancement, macOS affiche
> « développeur non identifié ». C'est normal : faites **clic droit sur l'app
> → Ouvrir**, puis confirmez. Cette étape n'est nécessaire qu'une seule fois.
>
> **Windows.** SmartScreen peut afficher un avertissement similaire :
> cliquez sur « Informations complémentaires » → « Exécuter quand même ».

## Prérequis côté utilisateur final

Le **test Mozilla Observatory fonctionne sans rien installer** : l'exécutable
seul suffit pour obtenir une note de sécurité des en-têtes HTTP.

Pour bénéficier en plus de **l'analyse WordPress (WPScan)**, il faut au moins
**l'un** des deux éléments suivants sur la machine (le programme installe
ensuite WPScan automatiquement, uniquement s'il est absent) :

- **Docker Desktop** *(recommandé)* — <https://www.docker.com/products/docker-desktop>
- **Ruby** — <https://www.ruby-lang.org/fr/documentation/installation/>

## Structure du projet

```
run.py                  Point d'entrée (lance l'interface)
build.py                Génère l'exécutable autonome
requirements.txt        Dépendances Python (fpdf2, certifi)
wpscan_analyzer/
  gui.py                Interface graphique en 3 écrans (Tkinter)
  runner.py             Détection / installation / exécution de WPScan
  observatory.py        Test Mozilla HTTP Observatory (API publique)
  report.py             Génération du rapport PDF combiné
  config.py             Sauvegarde du token et des préférences
```

## Confidentialité

- Le token WPScan n'est enregistré que si vous cochez « Mémoriser ». Il est
  alors stocké en local dans `~/.wpscan-analyzer/config.json`, fichier
  restreint à votre compte utilisateur (`chmod 600`).
- Aucune donnée n'est envoyée ailleurs qu'à l'API WPScan et au site scanné.
  Le rapport PDF reste sur votre machine.

## Licence

Distribué sous licence [MIT](LICENSE). WPScan est une marque et un outil tiers,
soumis à sa propre licence et à ses conditions d'utilisation.

