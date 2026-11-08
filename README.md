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

```powershell
python main.py --help
python -m scripts.memory_demo
```

`memory_demo` compare la mémoire utilisée pour lire un gros fichier avec
un générateur, avec une liste et avec `readlines()`.

## Tests

```powershell
python -m pytest
python -m ruff check .
```

On utilise `python -m pytest` plutôt que `pytest` car Windows bloque
parfois `pytest.exe`.

## Organisation du projet

```
main.py                  point d'entrée
log_engine/
  models.py              constantes des formats de logs
  exceptions.py          erreurs du programme
  cli.py                 ligne de commande
  ingestion/readers.py   lecture des fichiers
  parsers.py             conversion des lignes en dictionnaires
  filters.py             nettoyage des données avec filter()
  normalizer.py          normalisation des champs avec map()
  router.py              routage des événements avec match-case
  aggregation.py         comptage des événements avec defaultdict
  ip_analysis.py         analyse des IP avec set et frozenset
  bruteforce.py          détection des attaques par force brute
  rules.py               moteur de règles de sécurité
  audit.py               audit des variables avec globals() et locals()
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

## Avancement

- [x] Structure du projet et environnement
- [x] Formats de logs et données d'exemple
- [x] Lecture des fichiers avec un générateur
- [x] Lecture de plusieurs fichiers (`yield from`)
- [x] Parsing et routage (`match-case`)
- [x] Filtrage et transformation (`map`, `filter`, `lambda`)
- [x] Statistiques (`set`, `frozenset`, `defaultdict`)
- [x] Détection de force brute
- [x] Moteur de règles (`*args`, `**kwargs`)
- [x] Audit (`globals()`, `locals()`)
- [ ] Interface en ligne de commande complète
- [ ] Rapport final
