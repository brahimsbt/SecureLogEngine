# SecureLogEngine

Projet de Programmation en Python - ING3, ECE Paris.

Outil en ligne de commande qui lit et analyse des fichiers de logs de
sécurité. Les fichiers sont traités ligne par ligne, sans être chargés
entièrement en mémoire, pour pouvoir gérer des fichiers volumineux.

Équipe : TAGNE CHIBY Ellios, BENBOUJEMAA Manel, SABITY Brahim.

## Installation

Il faut Python 3.10 ou plus récent.

```powershell
git clone https://github.com/brahimsbt/SecureLogEngine.git
cd SecureLogEngine
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Si PowerShell bloque `Activate.ps1`, lancer une fois :

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

## Utilisation

Analyse des fichiers d'exemple :

```powershell
python main.py
```

Autres exemples :

```powershell
python main.py data/samples/auth.log --threshold 3
python main.py --blacklist data/samples/blacklist.txt --audit audit_report.json
python main.py --help
```

| Option | Rôle | Défaut |
|---|---|---|
| `fichiers` | fichiers de logs à analyser | les 3 fichiers de `data/samples/` |
| `--threshold` | échecs consécutifs pour détecter une force brute | 5 |
| `--blacklist` | fichier d'adresses IP blacklistées | `data/samples/blacklist.txt` |
| `--audit` | fichier JSON où exporter l'audit des variables | pas d'export |

Résultat sur les fichiers d'exemple :

```
=== SecureLogEngine : rapport d'analyse ===
Événements analysés : 49
Par niveau : INFO 22 | WARNING 22 | ERROR 3 | CRITICAL 2
Par utilisateur : admin 9 | bob 6 | alice 4 | root 3 | carol 3 | dave 2
...

=== Adresses IP ===
Blacklistées et actives : 192.0.2.150, 198.51.100.77
Suspectes non blacklistées : 10.0.0.15, 10.0.0.22, 10.0.0.31, 127.0.0.1, 198.51.100.23, 203.0.113.45

=== Alertes (4) ===
[brute_force] 203.0.113.45 : 6 échecs sur admin (attaque réussie)
[blacklist] 192.0.2.150 : IP blacklistée présente dans les logs
[blacklist] 198.51.100.77 : IP blacklistée présente dans les logs
[privilege] 203.0.113.45 : admin a obtenu des droits élevés
```

Démonstration de la mémoire utilisée :

```powershell
python -m scripts.memory_demo
```

## Rapport

Le rapport technique est le notebook `rapport.ipynb`. Il exécute le code
du projet sur les fichiers d'exemple, présente chaque module avec ses
résultats et contient deux graphiques (comptages et mémoire).

Il peut être lu directement sur GitHub, ou réexécuté dans VS Code en
choisissant l'environnement `.venv`.

## Tests

```powershell
python -m pytest
python -m pytest --cov=log_engine --cov-report=term-missing
python -m ruff check .
```

On utilise `python -m pytest` plutôt que `pytest` car Windows bloque
parfois `pytest.exe`.

## Organisation du projet

```
main.py                  point d'entrée
rapport.ipynb            rapport technique
log_engine/
  cli.py                 ligne de commande et affichage du rapport
  pipeline.py            chaîne complète de traitement en flux
  ingestion/readers.py   lecture des fichiers
  parsers.py             conversion des lignes en dictionnaires
  router.py              routage des événements avec match-case
  filters.py             nettoyage des données avec filter()
  normalizer.py          normalisation des champs avec map()
  aggregation.py         comptage des événements avec defaultdict
  ip_analysis.py         analyse des IP avec set et frozenset
  bruteforce.py          détection des attaques par force brute
  rules.py               moteur de règles de sécurité
  audit.py               audit des variables avec globals() et locals()
  models.py              constantes des formats de logs
  exceptions.py          erreurs du programme
data/samples/            fichiers de logs d'exemple
scripts/memory_demo.py   démonstration de la mémoire utilisée
tests/                   tests pytest
```

## Formats de logs

Trois formats sont acceptés :

- `auth.log` : texte, six champs séparés par ` | `
  (date, niveau, ip:port/protocole, utilisateur, événement, détails)
- `app_events.jsonl` : un objet JSON par ligne
- `connections.csv` : connexions réseau au format CSV

`blacklist.txt` contient une adresse IP par ligne.

Niveaux de sévérité, du moins grave au plus grave :
`INFO`, `WARNING`, `ERROR`, `CRITICAL`.

Les fichiers d'exemple contiennent volontairement une attaque par force
brute, un scan de ports et quelques lignes invalides pour tester le
programme.

## Correspondance avec le cahier des charges

| Exigence | Où |
|---|---|
| Générateur `yield` | `read_lines` dans `ingestion/readers.py` |
| Sous-générateur `yield from` | `read_sources` dans `ingestion/readers.py` |
| Lignes en dictionnaires, tuples `(IP, port, protocole)` | `parsers.py` |
| `filter()`, `lambda`, `filter(None, ...)` | `filters.py` |
| `map()` et f-strings | `normalizer.py` |
| `match` / `case` | `router.py` |
| `set`, `frozenset`, `\|`, `&`, `-`, `^` | `ip_analysis.py` |
| `defaultdict` | `aggregation.py`, `bruteforce.py` |
| `while`, `for`, `break`, `continue`, `else` de boucle | `bruteforce.py` |
| `apply_security_rules(*args, **kwargs)` | `rules.py` |
| `globals()` et `locals()` | `audit.py`, appelé dans `cli.py` |
| Traitement sans charger les fichiers en RAM | `pipeline.py`, mesuré dans `tests/test_pipeline.py` |

## Limites

- Les fichiers sont lus l'un après l'autre, sans fusion par date.
- Les analyses travaillent sur la liste des événements déjà filtrés.
- L'audit repère les secrets uniquement grâce au nom des variables.
