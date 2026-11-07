# -Sovraxi
Outil local et open source qui détecte les secrets potentiellement exposés dans un dépôt Git et aide les développeurs à les corriger avant leur publication.
# Sovraxi

Sovraxi est un outil local d’analyse de dépôts. Il recherche des secrets exposés et certains motifs courants de code ou de configuration à risque. Il n’envoie aucun fichier vers Internet.

## Lancer l’interface

```sh
python sovraxi.py
```

Le guide s’ouvre au démarrage. Choisis le dossier de ton projet, lance le scan, puis double-clique une détection pour lire son explication, son impact possible et une correction conseillée. À la fin, l’interface affiche le nombre de fichiers parcourus et émet le son système. Les secrets s’affichent en clair dans le tableau et le détail ; le bouton de copie est disponible dans le détail. Le bouton « Guide rapide » permet de rouvrir le guide.

Sur Arch Linux, l’interface nécessite Tkinter. Si son module ou sa bibliothèque système manque :

```sh
sudo pacman -S tk
```

## Lancer en terminal

```sh
python sovraxi.py scan /chemin/reel/vers/ton-projet
```

Le terminal affiche aussi le motif, l’emplacement, la raison de l’alerte, le risque possible et la correction conseillée. Les secrets sont affichés en clair par défaut. Ajoute `--redact-secrets` pour les masquer dans la sortie :

```sh
python sovraxi.py scan /chemin/reel/vers/ton-projet --redact-secrets
```

Le code de sortie vaut `0` sans alerte connue, `1` si une ou plusieurs alertes sont trouvées, et `2` en cas d’erreur.

## Contrôles actuels

- Secrets : identifiants AWS, jetons GitHub, en-têtes de clés privées et valeurs littérales associées aux noms `api_key`, `secret`, `password` ou `token`.
- Code source : motifs de sécurité pour Python, JavaScript/TypeScript, Go, Java/Kotlin, PHP, Ruby, C/C++, C# et Rust. Python bénéficie de contrôles AST (syntaxe et valeurs mutables par défaut) ; JavaScript passe par `node --check` si Node.js est installé ; C/C++ utilise Clang Static Analyzer si Clang est présent ; les fichiers JSON sont validés avec le parseur standard.
- APK et archives ZIP : scan des fichiers texte et des chaînes imprimables des fichiers compilés, détection de certaines permissions Android sensibles dans le manifeste.
- Binaires ELF et PE/EXE : recherche de secrets dans les chaînes imprimables ; lecture de protections ELF (PIE, RELRO, pile, canari) avec `readelf` et de protections PE (ASLR, DEP/NX) avec `objdump` quand ces outils sont installés.
- Configuration : mode debug activé, règles CORS avec origine joker, TLS désactivé et autres motifs décrits dans les détails des alertes.

Sovraxi ignore `.git`, les dépendances courantes et les liens symboliques. Les fichiers texte de plus de 2 Mio ne sont pas analysés ; les binaires sont limités à 100 Mio, les entrées d’archive à 32 Mio chacune et le contenu décompressé d’une archive à 256 Mio. Les limites produisent une alerte de couverture au lieu d’un résultat « propre » silencieux.

## Limites

Les règles sont heuristiques : une alerte demande une vérification humaine et l’absence d’alerte ne prouve pas qu’un dépôt est sans bug ou vulnérabilité. Les règles source recherchent des motifs ; elles ne comprennent pas tous les langages ni toutes les relations entre données et fonctions. L’analyse des APK ne décompile pas DEX et ne vérifie pas complètement la signature Android. ELF/PE reçoivent des contrôles de chaînes et de protections de compilation, pas une décompilation ni une analyse complète de leurs vulnérabilités. Cette version n’analyse pas l’historique Git et ne consulte pas de base de vulnérabilités de dépendances.

Pour tout secret réellement exposé, révoque-le ou renouvelle-le immédiatement. Le supprimer du fichier ne l’invalide pas.
