# WPScan Analyzer

Outil graphique tout-en-un pour scanner un site WordPress avec
[WPScan](https://wpscan.com/) et produire un **rapport PDF** clair, sans
connaître la ligne de commande.

Pensé pour les personnes qui gèrent des sites WordPress sous **Windows, macOS
ou Linux** : on saisit son token, l'URL du site, on clique, on récupère un PDF.

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

1. **Installation automatique de WPScan** *(uniquement si absent)* :
   - utilise **Docker** s'il est disponible (image `wpscanteam/wpscan`) ;
   - sinon installe le **gem Ruby** `wpscan`.
2. **Saisie simple** : token WPScan, URL du site, dossier de destination
   (le **Bureau** par défaut).
3. **Rapport PDF** généré dans le dossier choisi : version WordPress, thème,
   extensions, vulnérabilités connues et éléments intéressants.

Le token peut être mémorisé pour ne pas le ressaisir à chaque fois
(stocké dans `~/.wpscan-analyzer/config.json`, accès restreint au compte).

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

L'exécutable embarque tout le nécessaire **sauf le moteur WPScan**. Au premier
scan, le programme installe WPScan automatiquement. Il faut donc au moins
**l'un** des deux éléments suivants sur la machine :

- **Docker Desktop** *(recommandé)* — <https://www.docker.com/products/docker-desktop>
- **Ruby** — <https://www.ruby-lang.org/fr/documentation/installation/>

## Structure du projet

```
run.py                  Point d'entrée (lance l'interface)
build.py                Génère l'exécutable autonome
requirements.txt        Dépendances Python (fpdf2)
wpscan_analyzer/
  gui.py                Fenêtre graphique (Tkinter)
  runner.py             Détection / installation / exécution de WPScan
  report.py             Génération du rapport PDF
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

