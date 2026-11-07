#!/usr/bin/env python3
"""Local heuristic security and code-quality scanner for project files."""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

MAX_FILE_SIZE = 2 * 1024 * 1024
MAX_BINARY_SIZE = 100 * 1024 * 1024
MAX_ARCHIVE_ENTRY_SIZE = 32 * 1024 * 1024
MAX_ARCHIVE_TOTAL_SIZE = 256 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 2000
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "vendor", "__pycache__", ".mypy_cache"}


@dataclass(frozen=True)
class Rule:
    name: str
    category: str
    severity: str
    pattern: re.Pattern[str]
    explanation: str
    impact: str
    fix: str
    extensions: frozenset[str] | None = None
    secret: bool = False


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    category: str
    severity: str
    explanation: str
    impact: str
    fix: str
    masked_value: str = ""
    secret_value: str = ""
    location_type: str = "ligne"


def _rule(name: str, category: str, severity: str, pattern: str,
          explanation: str, impact: str, fix: str,
          extensions: set[str] | None = None, secret: bool = False) -> Rule:
    return Rule(name, category, severity, re.compile(pattern), explanation,
                impact, fix, frozenset(extensions) if extensions else None, secret)


RULES = (
    _rule(
        "AWS access key ID", "Secret", "Critique", r"\bAKIA[0-9A-Z]{16}\b",
        "Cette chaîne ressemble au préfixe d’un identifiant de clé AWS.",
        "Si la clé est réelle et publiée, une personne peut tenter de l’utiliser pour accéder aux ressources AWS.",
        "Révoque ou renouvelle la clé dans AWS IAM. Charge ensuite la nouvelle valeur depuis une variable d’environnement ou un gestionnaire de secrets.",
        secret=True,
    ),
    _rule(
        "Jeton GitHub", "Secret", "Critique",
        r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
        "Cette chaîne correspond à la forme connue d’un jeton GitHub.",
        "Un jeton valide peut donner accès aux dépôts et aux actions autorisés par ses permissions.",
        "Révoque le jeton dans les paramètres GitHub, crée-en un avec les permissions minimales, puis stocke-le hors du dépôt.",
        secret=True,
    ),
    _rule(
        "Clé privée", "Secret", "Critique",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "Un en-tête de clé privée est présent dans ce fichier.",
        "La clé peut permettre de déchiffrer des données ou de s’authentifier comme son propriétaire.",
        "Considère la clé comme compromise : révoque-la ou remplace-la auprès du service concerné et retire-la du dépôt.",
        secret=True,
    ),
    _rule(
        "Identifiant codé en dur", "Secret", "Élevée",
        r"(?i)\b(?:api[_-]?key|secret|password|token)\b\s*[:=]\s*[\"']?([^\s\"',;]{8,})",
        "Une affectation associée à un mot de passe, un jeton ou une clé contient une valeur littérale.",
        "Une valeur fixe peut être copiée avec le dépôt, les journaux ou les artefacts de compilation.",
        "Vérifie qu’il s’agit d’un vrai secret. Si oui, renouvelle-le, lis-le depuis l’environnement côté serveur et ajoute les fichiers locaux sensibles à .gitignore.",
        secret=True,
    ),
    _rule(
        "Exécution dynamique avec eval", "Code dangereux", "Élevée", r"(?<!literal_)\beval\s*\(",
        "eval exécute une chaîne comme du code au moment de l’exécution.",
        "Si la chaîne dépend d’une entrée contrôlée par un utilisateur, cela peut permettre l’exécution de code arbitraire.",
        "Remplace eval par un parseur de données ou une table explicite de fonctions autorisées. Ne passe jamais une entrée utilisateur directement à eval.",
        {".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    ),
    _rule(
        "Exécution dynamique avec exec", "Code dangereux", "Élevée", r"\bexec\s*\(",
        "exec compile et exécute du code construit à l’exécution.",
        "Une donnée non fiable intégrée au code peut entraîner une exécution de commandes ou une prise de contrôle du processus.",
        "Évite exec. Utilise une API dédiée ou une liste d’opérations autorisées ; valide toute donnée externe avant traitement.",
        {".py", ".pyw"},
    ),
    _rule(
        "Désérialisation pickle", "Désérialisation", "Élevée", r"\bpickle\.(?:load|loads)\s*\(",
        "pickle peut exécuter du code pendant le chargement d’un objet sérialisé.",
        "Charger un fichier pickle reçu d’une source non fiable peut exécuter du code arbitraire.",
        "N’utilise pickle qu’avec des données produites et protégées par ton application. Pour des données externes, préfère JSON ou un format sans exécution de code.",
        {".py", ".pyw"},
    ),
    _rule(
        "Chargement YAML potentiellement non sûr", "Désérialisation", "Élevée", r"\byaml\.load\s*\(",
        "yaml.load peut construire des objets Python selon le chargeur utilisé.",
        "Un document YAML non fiable peut provoquer l’exécution de code ou la création d’objets inattendus si un chargeur permissif est employé.",
        "Utilise yaml.safe_load pour les données ordinaires. Si un chargeur spécialisé est indispensable, limite les sources et documente le besoin.",
        {".py", ".pyw"},
    ),
    _rule(
        "TLS désactivé dans une requête", "Configuration réseau", "Élevée", r"\bverify\s*=\s*False\b",
        "La vérification du certificat TLS semble désactivée.",
        "Un attaquant sur le réseau pourrait intercepter ou modifier les échanges chiffrés sans déclencher l’erreur de certificat attendue.",
        "Retire verify=False et corrige la chaîne de certificats. Pour une autorité interne, configure son certificat racine au lieu de désactiver la vérification.",
        {".py", ".pyw"},
    ),
    _rule(
        "Commande shell avec shell=True", "Injection de commande", "Élevée", r"\bshell\s*=\s*True\b",
        "Le processus semble demander l’interprétation de la commande par un shell.",
        "Si une partie de la commande vient d’une entrée externe, des caractères spéciaux peuvent exécuter des commandes supplémentaires.",
        "Passe une liste d’arguments à subprocess.run sans shell=True. Valide les valeurs reçues et n’assemble pas une commande depuis une chaîne non fiable.",
        {".py", ".pyw"},
    ),
    _rule(
        "Appel système shell", "Injection de commande", "À examiner", r"\bos\.system\s*\(",
        "os.system transmet une chaîne de commande à un shell.",
        "La concaténation avec une entrée externe peut rendre possible une injection de commande.",
        "Utilise subprocess.run avec une liste d’arguments et sans shell=True ; valide les entrées selon leur format attendu.",
        {".py", ".pyw"},
    ),
    _rule(
        "TLS non vérifié en Go", "Configuration réseau", "Élevée", r"InsecureSkipVerify\s*:\s*true",
        "La configuration TLS semble ignorer la validation du certificat serveur.",
        "La connexion reste chiffrée mais ne prouve plus correctement l’identité du serveur, ce qui ouvre la voie à une interception.",
        "Retire InsecureSkipVerify et installe ou configure l’autorité de certification attendue.",
        {".go"},
    ),
    _rule(
        "Injection HTML potentielle", "Injection côté navigateur", "Élevée",
        r"\.(?:innerHTML|outerHTML)\s*=|dangerouslySetInnerHTML",
        "Une valeur est injectée directement dans une zone interprétée comme HTML.",
        "Si elle contient des données contrôlées par un utilisateur, du script peut s’exécuter dans le navigateur d’autres personnes (XSS).",
        "Préfère textContent ou le rendu texte de ton framework. Si du HTML est nécessaire, assainis-le avec une bibliothèque dédiée et une politique stricte.",
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    ),
    _rule(
        "Exécution de commande Node.js", "Injection de commande", "Élevée",
        r"\b(?:child_process\.)?(?:exec|execSync)\s*\(",
        "exec interprète la commande via un shell.",
        "L’ajout de données externes à cette commande peut permettre une injection de commande sur la machine du serveur.",
        "Préfère execFile/spawn avec un exécutable et des arguments séparés. Valide les entrées et évite l’interpolation de chaînes de commande.",
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    ),
    _rule(
        "Vérification TLS Node.js désactivée", "Configuration réseau", "Élevée",
        r"rejectUnauthorized\s*:\s*false",
        "La validation du certificat TLS semble désactivée.",
        "Le client peut accepter un serveur usurpé et exposer les données échangées à une interception réseau.",
        "Retire rejectUnauthorized: false et corrige la configuration de certificats du client.",
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    ),
    _rule(
        "Requête SQL construite avec f-string", "Injection SQL", "Élevée",
        r"\.(?:execute|executemany)\s*\(\s*f[\"']",
        "Une requête SQL semble être interpolée dans une f-string.",
        "Si une valeur provient d’un utilisateur, elle peut modifier la requête et lire ou changer des données non autorisées.",
        "Utilise les paramètres de la bibliothèque SQL (placeholders) et passe les valeurs séparément. N’insère jamais directement une entrée dans la chaîne SQL.",
        {".py", ".pyw"},
    ),
    _rule(
        "SQL formaté dynamiquement en Go", "Injection SQL", "À examiner",
        r"\.(?:Query|QueryRow|Exec|Prepare)\s*\(\s*fmt\.Sprintf\s*\(",
        "Une requête SQL semble être assemblée avec fmt.Sprintf.",
        "L’insertion directe d’une entrée externe dans SQL peut contourner les contrôles et modifier les résultats de la requête.",
        "Utilise les placeholders du pilote SQL ($1, ?, etc.) et transmets les valeurs comme arguments séparés.",
        {".go"},
    ),
    _rule(
        "Mode debug activé", "Configuration", "À examiner",
        r"(?i)\bdebug\b\s*[:=]\s*(?:true|1|on)\b",
        "Une option nommée debug semble activée dans ce fichier.",
        "En production, le mode debug peut révéler des traces, des chemins locaux ou des détails internes.",
        "Vérifie l’environnement ciblé. Désactive debug en production et lis ce réglage depuis une configuration propre à l’environnement.",
        {".py", ".pyw", ".yaml", ".yml", ".json", ".toml", ".ini", ".env"},
    ),
    _rule(
        "Origine CORS ouverte", "Configuration réseau", "À examiner",
        r"(?i)(?:access-control-allow-origin|allow_origins?)\s*[:=]\s*[\"']?\*[\"']?",
        "La règle CORS semble autoriser toutes les origines.",
        "Un site tiers peut effectuer certaines requêtes navigateur vers l’application ; le risque dépend des cookies et des autres contrôles d’accès.",
        "Remplace le joker par la liste précise des origines autorisées et vérifie séparément la configuration des cookies et des identifiants.",
        {".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml", ".toml"},
    ),
    _rule(
        "Désérialisation Java", "Désérialisation", "Élevée",
        r"\bObjectInputStream\b|\.readObject\s*\(",
        "Le code semble désérialiser un objet Java natif.",
        "Des données sérialisées non fiables peuvent provoquer l’instanciation de classes inattendues et parfois l’exécution de code.",
        "Évite la désérialisation Java native pour les données non fiables. Utilise un format de données simple et valide strictement les types attendus.",
        {".java", ".kt", ".scala"},
    ),
    _rule(
        "Commande système Java", "Injection de commande", "Élevée",
        r"Runtime\.getRuntime\s*\(\)\s*\.\s*exec\s*\(",
        "L’application semble lancer une commande système depuis Java.",
        "Si la commande inclut une donnée externe, elle peut exécuter des commandes non prévues sur la machine.",
        "Évite de construire une commande à partir d’une chaîne. Si un processus est nécessaire, utilise un exécutable fixe et des arguments séparés après validation stricte.",
        {".java", ".kt", ".scala"},
    ),
    _rule(
        "Désérialisation PHP", "Désérialisation", "Élevée", r"\bunserialize\s*\(",
        "unserialize convertit une chaîne en objets PHP.",
        "Des données contrôlées par un utilisateur peuvent créer des objets dangereux et déclencher des méthodes inattendues.",
        "Évite unserialize sur des données externes. Préfère JSON et valide son schéma ; si nécessaire, limite strictement les classes autorisées.",
        {".php", ".phtml"},
    ),
    _rule(
        "Exécution de code PHP", "Code dangereux", "Élevée",
        r"\b(?:eval|exec|system|shell_exec|passthru)\s*\(",
        "Une fonction PHP semble exécuter du code ou une commande système.",
        "Une entrée externe peut transformer cet appel en exécution de code ou commande arbitraire.",
        "Supprime l’exécution dynamique si possible. Sinon, utilise une liste d’actions autorisées et des arguments séparés ; ne concatène jamais une entrée utilisateur.",
        {".php", ".phtml"},
    ),
    _rule(
        "Désérialisation Ruby", "Désérialisation", "Élevée", r"\bMarshal\.load\s*\(",
        "Marshal.load reconstruit des objets Ruby depuis des données sérialisées.",
        "Charger une donnée Marshal non fiable peut exécuter des méthodes arbitraires lors de la reconstruction.",
        "N’utilise Marshal qu’avec des données internes authentifiées. Pour les entrées externes, préfère JSON et valide les valeurs.",
        {".rb", ".rake"},
    ),
    _rule(
        "Fonction C potentiellement non bornée", "Mémoire native", "Élevée",
        r"\b(?:gets|strcpy|strcat|sprintf)\s*\(",
        "Le code C/C++ utilise une fonction qui ne vérifie pas toujours la taille de destination.",
        "Une entrée trop longue peut écraser la mémoire et provoquer un crash ou une exécution de code.",
        "Remplace l’appel par une API qui reçoit et contrôle la taille du tampon, puis vérifie les longueurs avant chaque copie.",
        {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx"},
    ),
    _rule(
        "Désérialisation .NET", "Désérialisation", "Élevée",
        r"\bBinaryFormatter\b|\.Deserialize\s*\(",
        "Le code .NET semble utiliser un mécanisme de désérialisation d’objets.",
        "La désérialisation d’une donnée non fiable peut instancier des objets dangereux et conduire à l’exécution de code.",
        "Évite BinaryFormatter et les formats polymorphes non fiables. Utilise un format de données simple avec une liste de types autorisés.",
        {".cs", ".vb"},
    ),
    _rule(
        "Bloc unsafe Rust", "Mémoire native", "À examiner", r"\bunsafe\s*\{",
        "Ce bloc Rust contourne certaines garanties du compilateur.",
        "Une erreur de pointeur ou de durée de vie peut entraîner un comportement indéfini ou une corruption mémoire.",
        "Réduis la taille du bloc unsafe, documente ses invariants et ajoute une abstraction sûre autour de l’opération.",
        {".rs"},
    ),
    _rule(
        "Comparaison SQL formatée en JavaScript", "Injection SQL", "À examiner",
        r"\b(?:query|execute)\s*\([^\n;]*\+\s*[A-Za-z_$]",
        "La requête semble concaténer du texte avec une valeur dynamique.",
        "Une entrée externe peut modifier la requête et accéder à des données non autorisées.",
        "Utilise les paramètres préparés du pilote SQL et transmets les valeurs séparément.",
        {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    ),
)


def mask(value: str) -> str:
    if len(value) <= 4:
        return "[MASQUÉ]"
    return value[:2] + "*" * min(len(value) - 4, 12) + value[-2:]


def scan_file(root: Path, path: Path) -> list[Finding]:
    try:
        size = path.stat().st_size
        if size > MAX_BINARY_SIZE:
            return [_coverage_finding(
                str(path.relative_to(root)), "Fichier trop volumineux pour le scan local",
                f"La taille dépasse la limite configurée de {MAX_BINARY_SIZE // (1024 * 1024)} Mio.",
                "Ce fichier n’a pas été examiné ; il peut contenir des problèmes qui ne figurent donc pas dans le rapport.",
                "Scanne-le séparément avec un analyseur adapté ou augmente la limite locale après avoir vérifié l’espace disponible.",
            )]
        if zipfile.is_zipfile(path):
            return _scan_archive(root, path)
        content = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"impossible de lire {path}: {exc.strerror or exc}") from exc

    label = str(path.relative_to(root))
    suffix = path.suffix.lower()
    if b"\0" in content or content.startswith((b"\x7fELF", b"MZ")):
        findings = _scan_binary(label, content)
        if content.startswith(b"\x7fELF"):
            findings.extend(_analyze_elf(label, path))
        elif content.startswith(b"MZ"):
            findings.extend(_analyze_pe(label, path))
        else:
            findings.append(_coverage_finding(
                label, "Analyse binaire limitée aux chaînes imprimables",
                "Ce format binaire n’est pas décompilé par Sovraxi ; seules les chaînes lisibles ont été examinées pour repérer des secrets.",
                "Les défauts de logique, failles mémoire et vulnérabilités internes au bytecode peuvent ne pas être détectés.",
                "Utilise un analyseur adapté au format et traite cette alerte comme une couverture partielle.",
            ))
        return findings
    if len(content) > MAX_FILE_SIZE:
        return [_coverage_finding(
            label, "Fichier trop volumineux pour le scan texte",
            f"La taille dépasse la limite texte de {MAX_FILE_SIZE // (1024 * 1024)} Mio.",
            "Ce fichier n’a pas été examiné.",
            "Scanne-le séparément ou ajuste la limite dans Sovraxi.",
        )]
    findings = _scan_content(label, content, suffix)
    if suffix in {".js", ".mjs", ".cjs"}:
        findings.extend(_scan_javascript_syntax(label, path))
    if suffix in {".c", ".cc", ".cpp", ".cxx"}:
        findings.extend(_scan_clang(label, path))
    return findings


def _scan_content(label: str, content: bytes, suffix: str,
                  binary_secrets_only: bool = False) -> list[Finding]:
    if b"\0" in content:
        return _scan_binary(label, content) if binary_secrets_only else []

    findings: list[Finding] = []
    if not binary_secrets_only:
        findings.extend(_scan_pem_keys(label, content))
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.decode("utf-8", errors="replace")
        for rule in RULES:
            if binary_secrets_only and not rule.secret:
                continue
            if rule.extensions is not None and suffix not in rule.extensions:
                continue
            match = rule.pattern.search(line)
            if match is None:
                continue
            if rule.name == "Chargement YAML potentiellement non sûr" and "SafeLoader" in line:
                continue
            if rule.name == "Clé privée":
                continue
            captured = match.group(1) if match.lastindex else match.group(0)
            # A reference to an environment variable is not itself a hard-coded secret.
            if rule.name == "Identifiant codé en dur" and re.match(
                r"(?i)^(?:os\.environ|process\.env|os\.getenv|getenv\(|env\(|secret\()", captured
            ):
                continue
            findings.append(Finding(
                path=label, line=line_number, rule=rule.name,
                category=rule.category, severity=rule.severity,
                explanation=rule.explanation, impact=rule.impact, fix=rule.fix,
                masked_value=mask(captured) if rule.secret else "",
                secret_value=captured if rule.secret else "",
            ))

    if not binary_secrets_only and suffix in {".py", ".pyw"}:
        try:
            syntax_tree = ast.parse(content.decode("utf-8-sig"), filename=label)
        except (SyntaxError, UnicodeDecodeError) as exc:
            line_number = getattr(exc, "lineno", None) or 1
            detail = getattr(exc, "msg", None) or "le fichier n’est pas un texte Python UTF-8 valide"
            findings.append(Finding(
                path=label, line=line_number,
                rule="Erreur de syntaxe Python", category="Bug de syntaxe",
                severity="Bloquante",
                explanation=f"Python ne peut pas analyser ce fichier : {detail}.",
                impact="Le module peut échouer au chargement et empêcher le programme ou une commande de démarrer.",
                fix="Ouvre cette ligne dans l’éditeur, corrige la syntaxe signalée, puis relance la vérification Python.",
            ))
        else:
            findings.extend(_scan_python_ast(label, syntax_tree))
    if not binary_secrets_only and suffix == ".json":
        try:
            json.loads(content)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            findings.append(Finding(
                path=label, line=getattr(exc, "lineno", 1) or 1,
                rule="Erreur de syntaxe JSON", category="Bug de syntaxe",
                severity="Bloquante",
                explanation=f"Le document JSON ne peut pas être analysé : {getattr(exc, 'msg', str(exc))}.",
                impact="Un programme qui lit ce fichier peut échouer au chargement ou ignorer sa configuration.",
                fix="Corrige la syntaxe JSON près de la position indiquée, puis valide à nouveau le fichier.",
            ))
    return findings


PEM_KEY_PATTERN = re.compile(
    rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    rb".*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.DOTALL,
)


def _scan_pem_keys(label: str, content: bytes) -> list[Finding]:
    rule = next(rule for rule in RULES if rule.name == "Clé privée")
    findings: list[Finding] = []
    complete_matches = list(PEM_KEY_PATTERN.finditer(content))
    for match in complete_matches:
        value = match.group(0).decode("ascii", errors="replace")
        findings.append(Finding(
            path=label, line=content[:match.start()].count(b"\n") + 1,
            rule=rule.name, category=rule.category, severity=rule.severity,
            explanation=rule.explanation, impact=rule.impact, fix=rule.fix,
            masked_value=mask(value), secret_value=value,
        ))
    header_pattern = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
    for header in header_pattern.finditer(content):
        if any(match.start() <= header.start() < match.end() for match in complete_matches):
            continue
        value = content[header.start():header.start() + 65536].decode("ascii", errors="replace")
        findings.append(Finding(
            path=label, line=content[:header.start()].count(b"\n") + 1,
            rule="En-tête de clé privée (bloc incomplet)", category=rule.category,
            severity=rule.severity,
            explanation="Un en-tête de clé privée est présent, mais le bloc complet n’a pas été retrouvé dans ce fichier.",
            impact=rule.impact,
            fix=f"{rule.fix} Vérifie aussi si la clé est coupée ou répartie sur plusieurs fichiers.",
            masked_value=mask(value), secret_value=value,
        ))
    return findings


def _scan_javascript_syntax(label: str, path: Path) -> list[Finding]:
    if not shutil.which("node"):
        return []
    try:
        result = subprocess.run(["node", "--check", str(path)], capture_output=True,
                                text=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode == 0:
        return []
    first_line = (result.stderr or "").splitlines()[:1]
    location = re.search(r":(\d+)(?::\d+)?$", first_line[0]) if first_line else None
    line = int(location.group(1)) if location else 1
    message = next((m.group(1) for text in (result.stderr or "").splitlines()
                    if (m := re.search(r"SyntaxError:\s*(.+)", text))),
                   "Node.js a signalé une erreur de syntaxe.")
    return [Finding(
        path=label, line=line, rule="Erreur de syntaxe JavaScript",
        category="Bug de syntaxe", severity="Bloquante",
        explanation=message,
        impact="Le moteur JavaScript peut refuser de charger ce fichier et empêcher une partie de l’application de démarrer.",
        fix="Corrige l’expression indiquée puis relance le scan. L’analyse utilise node --check sans exécuter le fichier.",
    )]


def _scan_clang(label: str, path: Path) -> list[Finding]:
    if not shutil.which("clang"):
        return []
    try:
        result = subprocess.run(
            ["clang", "--analyze", "-o", os.devnull, str(path)],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    findings: list[Finding] = []
    diagnostic = re.compile(r"^.+?:(\d+):\d+:\s+warning:\s+(.+?)(?:\s+\[[^]]+\])?$")
    for raw_line in result.stderr.splitlines():
        match = diagnostic.match(raw_line)
        if not match:
            continue
        message = match.group(2)
        high_risk = re.search(r"use-after-free|null pointer|buffer overflow|out-of-bounds|uninitialized", message, re.I)
        findings.append(Finding(
            path=label, line=int(match.group(1)),
            rule="Alerte Clang Static Analyzer", category="Analyse C/C++",
            severity="Élevée" if high_risk else "À examiner",
            explanation=message,
            impact="L’analyse statique de Clang signale un chemin de code potentiellement incorrect ; vérifie les conditions et les valeurs concernées.",
            fix="Ouvre l’emplacement indiqué, inspecte le chemin signalé et corrige la cause. Le diagnostic Clang est une piste à confirmer.",
        ))
    return findings


def _scan_python_ast(label: str, tree: ast.AST) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        defaults = node.args.defaults + [item for item in node.args.kw_defaults if item is not None]
        mutable_default = next((item for item in defaults if _is_mutable_default(item)), None)
        if mutable_default is None:
            continue
        findings.append(Finding(
            path=label, line=mutable_default.lineno,
            rule="Valeur mutable par défaut", category="Bug Python", severity="Moyenne",
            explanation=f"La fonction {node.name} utilise une liste ou un dictionnaire créé dans sa signature.",
            impact="Python réutilise le même objet par défaut à chaque appel. Une modification lors d’un appel peut donc affecter les suivants.",
            fix="Utilise None comme valeur par défaut, puis crée une nouvelle liste ou un nouveau dictionnaire dans le corps de la fonction.",
        ))
    return findings


def _is_mutable_default(node: ast.AST) -> bool:
    if isinstance(node, (ast.List, ast.Dict, ast.Set)):
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"list", "dict", "set"}
        and not node.args
        and not node.keywords
    )


def _scan_binary(label: str, content: bytes) -> list[Finding]:
    """Search printable binary strings for secrets; this is not decompilation."""
    findings: list[Finding] = []
    findings.extend(_scan_pem_keys(label, content))
    patterns = (
        re.compile(rb"[\x20-\x7e]{5,}"),
        re.compile(rb"(?:[\x20-\x7e]\x00){5,}"),
    )
    index = 0
    for pattern in patterns:
        for match in pattern.finditer(content):
            index += 1
            raw = match.group(0)
            text = raw.decode("utf-16-le" if b"\x00" in raw else "ascii", errors="ignore")
            for rule in RULES:
                if not rule.secret or rule.name == "Clé privée":
                    continue
                hit = rule.pattern.search(text)
                if hit is None:
                    continue
                value = hit.group(1) if hit.lastindex else hit.group(0)
                findings.append(Finding(
                    path=label, line=index, rule=f"{rule.name} (chaîne de binaire)",
                    category="Secret dans un binaire", severity=rule.severity,
                    explanation="Une chaîne imprimable présente dans ce binaire correspond à un motif de secret connu.",
                    impact=rule.impact,
                    fix=f"{rule.fix} Reconstruis ensuite le binaire sans intégrer le secret.",
                    masked_value=mask(value), secret_value=value,
                    location_type="chaîne",
                ))
    return findings


def _archive_finding(label: str, rule: str, explanation: str, impact: str,
                     fix: str, severity: str = "À examiner") -> Finding:
    return Finding(
        path=label, line=1, rule=rule, category="Application empaquetée",
        severity=severity, explanation=explanation, impact=impact, fix=fix,
        location_type="archive",
    )


def _coverage_finding(label: str, rule: str, explanation: str,
                      impact: str, fix: str) -> Finding:
    return Finding(
        path=label, line=1, rule=rule, category="Couverture du scan",
        severity="À examiner", explanation=explanation, impact=impact,
        fix=fix, location_type="fichier",
    )


APK_PERMISSIONS = {
    "android.permission.READ_SMS": "Lecture des SMS",
    "android.permission.RECEIVE_SMS": "Réception des SMS",
    "android.permission.SEND_SMS": "Envoi de SMS",
    "android.permission.READ_CONTACTS": "Lecture des contacts",
    "android.permission.READ_CALL_LOG": "Lecture du journal d’appels",
    "android.permission.ACCESS_FINE_LOCATION": "Localisation précise",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Installation d’autres applications",
    "android.permission.SYSTEM_ALERT_WINDOW": "Affichage par-dessus les autres applications",
    "android.permission.QUERY_ALL_PACKAGES": "Inventaire des applications installées",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Accès au service d’accessibilité",
}


def _scan_apk_manifest(label: str, content: bytes) -> list[Finding]:
    findings: list[Finding] = []
    for permission, description in APK_PERMISSIONS.items():
        if permission.encode() in content or permission.encode("utf-16-le") in content:
            findings.append(_archive_finding(
                label, f"Permission Android sensible : {permission}",
                f"Le manifeste semble demander la permission « {description} ».",
                "Cette permission peut donner accès à des données ou capacités sensibles. Sa présence seule ne prouve pas un abus.",
                "Vérifie que la fonction de l’application en a réellement besoin, demande la permission au moment opportun et limite l’accès aux données collectées.",
            ))
    for marker, title, explanation, fix in (
        (b'android:debuggable="true"', "Application Android en mode debug",
         "Le manifeste texte indique que le mode debug est activé.",
         "Désactive debuggable dans la version de production et reconstruis l’APK."),
        (b'android:usesCleartextTraffic="true"', "Trafic HTTP en clair autorisé",
         "Le manifeste texte autorise des connexions HTTP non chiffrées.",
         "Désactive cette option et utilise HTTPS, sauf exception documentée et limitée."),
    ):
        if marker in content:
            findings.append(_archive_finding(
                label, title, explanation,
                "Des données réseau peuvent être exposées ou modifiées sur un réseau non fiable.",
                fix, "Élevée",
            ))
    return findings


def _scan_archive(root: Path, path: Path) -> list[Finding]:
    label = str(path.relative_to(root))
    findings: list[Finding] = []
    if path.suffix.lower() in {".apk", ".aab"}:
        findings.append(_coverage_finding(
            label, "Bytecode Android non décompilé",
            "Sovraxi inspecte le manifeste, les fichiers lisibles et les chaînes de l’APK/AAB, mais ne décompile pas DEX en code source.",
            "Des failles dans le flot de contrôle, les appels natifs ou les bibliothèques embarquées peuvent rester invisibles.",
            "Complète l’audit avec un moteur spécialisé Android/DEX avant de conclure à l’absence de vulnérabilité.",
        ))
    total_uncompressed = 0
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                return [_archive_finding(
                    label, "Archive trop volumineuse à inspecter complètement",
                    f"L’archive contient {len(entries)} entrées, au-delà de la limite locale de {MAX_ARCHIVE_ENTRIES}.",
                    "Une partie de son contenu ne sera pas analysée.",
                    "Réduis ou divise l’archive, puis relance l’analyse sur chaque partie.", "À examiner",
                )]
            for entry in entries:
                if entry.is_dir():
                    continue
                total_uncompressed += entry.file_size
                member_label = f"{label}!/{entry.filename}"
                if entry.file_size > MAX_ARCHIVE_ENTRY_SIZE:
                    findings.append(_coverage_finding(
                        member_label, "Fichier d’archive trop volumineux",
                        f"L’entrée dépasse la limite décompressée de {MAX_ARCHIVE_ENTRY_SIZE // (1024 * 1024)} Mio.",
                        "Cette entrée n’a pas été inspectée.",
                        "Scanne le fichier extrait séparément ou ajuste la limite après vérification.",
                    ))
                    continue
                if total_uncompressed > MAX_ARCHIVE_TOTAL_SIZE:
                    findings.append(_archive_finding(
                        label, "Limite de décompression atteinte",
                        "L’analyse a atteint sa limite de taille décompressée pour cette archive.",
                        "Des fichiers restants de l’archive n’ont pas été examinés.",
                        "Scanne séparément les fichiers nécessaires ou augmente la limite après avoir vérifié la provenance de l’archive.",
                    ))
                    break
                try:
                    with archive.open(entry) as stream:
                        content = stream.read(MAX_ARCHIVE_ENTRY_SIZE + 1)
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    continue
                if len(content) > MAX_ARCHIVE_ENTRY_SIZE:
                    continue
                member_suffix = Path(entry.filename).suffix.lower()
                if path.suffix.lower() == ".apk" and Path(entry.filename).name == "AndroidManifest.xml":
                    findings.extend(_scan_apk_manifest(member_label, content))
                if b"\0" in content:
                    findings.extend(_scan_binary(member_label, content))
                else:
                    findings.extend(_scan_content(member_label, content, member_suffix))
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        findings.append(_coverage_finding(
            label, "Archive illisible",
            f"Sovraxi n’a pas pu parcourir cette archive : {exc}.",
            "Les fichiers contenus dans cette archive n’ont pas été analysés.",
            "Vérifie l’intégrité de l’archive et relance l’analyse.",
        ))
    return findings


def _external_output(arguments: list[str], timeout: int = 15) -> str:
    if not shutil.which(arguments[0]):
        return ""
    try:
        result = subprocess.run(arguments, capture_output=True, text=True,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout if result.returncode == 0 else ""


def _binary_finding(label: str, rule: str, explanation: str,
                    impact: str, fix: str) -> Finding:
    return Finding(
        path=label, line=1, rule=rule, category="Protection binaire",
        severity="À examiner", explanation=explanation, impact=impact,
        fix=fix, location_type="binaire",
    )


def _analyze_elf(label: str, path: Path) -> list[Finding]:
    output = _external_output(["readelf", "-W", "-h", "-l", "-d", "-s", str(path)])
    if not output:
        return [_coverage_finding(
            label, "Protections ELF non vérifiées",
            "readelf est absent, a échoué ou a dépassé son délai ; Sovraxi n’a pas pu examiner les protections de compilation.",
            "Seule la recherche locale de chaînes de secrets a été effectuée sur ce binaire.",
            "Installe binutils (readelf) puis relance l’analyse.",
        )]
    findings: list[Finding] = []
    header = re.search(r"Type:\s+(\w+)", output)
    has_interpreter = " INTERP " in output
    if header and header.group(1) == "EXEC" and has_interpreter:
        findings.append(_binary_finding(
            label, "Exécutable ELF sans PIE détecté",
            "Le binaire semble être un exécutable positionné à une adresse fixe.",
            "L’absence de PIE réduit l’efficacité de l’ASLR contre certaines corruptions mémoire.",
            "Active la compilation PIE dans la chaîne de build si le programme et sa plateforme le permettent.",
        ))
    stack_lines = [line for line in output.splitlines() if "GNU_STACK" in line]
    if any(re.search(r"\bRWE\b", line) for line in stack_lines):
        findings.append(_binary_finding(
            label, "Pile ELF exécutable",
            "Le segment GNU_STACK semble autoriser à la fois l’écriture et l’exécution.",
            "Une corruption mémoire pourrait plus facilement exécuter des données déposées sur la pile.",
            "Recompile avec une pile non exécutable et vérifie les options de l’éditeur de liens.",
        ))
    if "GNU_RELRO" not in output:
        findings.append(_binary_finding(
            label, "RELRO absent du binaire ELF",
            "Aucun segment GNU_RELRO n’a été trouvé par readelf.",
            "Certaines tables de liaison restent modifiables après le démarrage.",
            "Active RELRO dans l’éditeur de liens ; utilise aussi l’option NOW pour obtenir le mode complet.",
        ))
    elif not re.search(r"BIND_NOW|FLAGS\s+.*\bNOW\b|FLAGS_1\s+.*\bNOW\b", output):
        findings.append(_binary_finding(
            label, "RELRO partiel détecté",
            "GNU_RELRO est présent, mais readelf n’a pas trouvé l’activation de NOW.",
            "La protection des tables de liaison peut rester partielle.",
            "Active RELRO complet avec NOW dans les options de l’éditeur de liens.",
        ))
    if "__stack_chk_fail" not in output:
        findings.append(_binary_finding(
            label, "Canari de pile non détecté",
            "Le symbole __stack_chk_fail n’apparaît pas dans la table examinée.",
            "La protection contre certaines corruptions de pile peut manquer ; les symboles supprimés ou statiques limitent la fiabilité de ce contrôle.",
            "Active les protections de pile du compilateur et vérifie le binaire final, en tenant compte du type de liaison.",
        ))
    findings.append(_coverage_finding(
        label, "Code ELF non décompilé",
        "Sovraxi a vérifié quelques protections de compilation et chaînes lisibles, sans analyser le flot d’exécution du binaire.",
        "Les vulnérabilités de logique, d’accès mémoire ou de dépendances peuvent rester invisibles.",
        "Complète l’audit avec une analyse binaire spécialisée.",
    ))
    return findings


def _analyze_pe(label: str, path: Path) -> list[Finding]:
    output = _external_output(["objdump", "-p", str(path)])
    match = re.search(r"DllCharacteristics\s+([0-9a-fA-F]+)", output)
    if not match:
        return [_coverage_finding(
            label, "Protections PE non vérifiées",
            "objdump est absent, a échoué ou n’a pas reconnu les caractéristiques PE de ce fichier.",
            "Seule la recherche locale de chaînes de secrets a pu être effectuée.",
            "Installe binutils (objdump) et vérifie le format du binaire.",
        )]
    flags = int(match.group(1), 16)
    findings: list[Finding] = []
    for bit, title, explanation, fix in (
        (0x0040, "ASLR non activé", "Le binaire PE ne déclare pas DYNAMIC_BASE.",
         "Active ASLR dans la configuration de l’éditeur de liens et reconstruis l’application."),
        (0x0100, "DEP/NX non activé", "Le binaire PE ne déclare pas NX_COMPAT.",
         "Active DEP/NX dans la configuration de l’éditeur de liens et reconstruis l’application."),
    ):
        if not flags & bit:
            findings.append(_binary_finding(
                label, title, explanation,
                "Une mitigation de mémoire standard semble absente ; cela augmente l’impact potentiel de certaines corruptions, sans prouver une vulnérabilité exploitable.",
                fix,
            ))
    findings.append(_coverage_finding(
        label, "Code PE non décompilé",
        "Sovraxi a vérifié les indicateurs ASLR/DEP et les chaînes lisibles, sans analyser le flot d’exécution du programme.",
        "Les failles de logique, les corruptions mémoire et les vulnérabilités de dépendances peuvent rester invisibles.",
        "Complète l’audit avec une analyse binaire spécialisée.",
    ))
    return findings


def scan_with_stats(root: Path) -> tuple[list[Finding], int]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("le chemin à analyser doit être un dossier")

    findings: list[Finding] = []
    scanned_files = 0
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if name not in SKIP_DIRS]
        current_path = Path(current)
        for filename in files:
            path = current_path / filename
            if path.is_symlink() or not path.is_file():
                continue
            scanned_files += 1
            findings.extend(scan_file(root, path))
    return findings, scanned_files


def scan(root: Path) -> list[Finding]:
    """Compatibilité pour les appels qui ne nécessitent pas le bilan du scan."""
    findings, _scanned_files = scan_with_stats(root)
    return findings


def print_finding(finding: Finding, redact_secrets: bool = False) -> None:
    print(f"\n[{finding.severity}] {finding.rule} — {finding.category}")
    print(f"  Emplacement : {finding.path} · {finding.location_type} {finding.line}")
    if finding.secret_value:
        value = finding.masked_value if redact_secrets else finding.secret_value
        print(f"  Valeur      : {value}")
    print(f"  Détection   : {finding.explanation}")
    print(f"  Risque      : {finding.impact}")
    print(f"  Correction  : {finding.fix}")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="sovraxi", description="Analyse locale des secrets et problèmes de sécurité courants."
    )
    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser("scan", help="analyser les fichiers d’un dossier")
    scan_parser.add_argument("path", nargs="?", default=".", help="dossier du projet (défaut : dossier courant)")
    scan_parser.add_argument("--quiet", action="store_true", help="afficher uniquement le résumé")
    scan_parser.add_argument(
        "--redact-secrets", action="store_true",
        help="masquer les secrets dans la sortie du terminal",
    )
    subparsers.add_parser("gui", help="ouvrir l’interface graphique")
    args = parser.parse_args()

    if args.command in (None, "gui"):
        try:
            from gui import launch
        except ImportError as exc:
            print("sovraxi : Tkinter indisponible. Sur Arch Linux : sudo pacman -S tk", file=sys.stderr)
            print(f"Détail : {exc}", file=sys.stderr)
            return 2
        launch()
        return 0

    try:
        findings, scanned_files = scan_with_stats(Path(args.path))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"sovraxi : {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        for finding in findings:
            print_finding(finding, redact_secrets=args.redact_secrets)
        print(f"\n{scanned_files} fichier(s) parcouru(s).")
    if findings:
        print(f"\n{len(findings)} élément(s) à examiner. Les contrôles sont heuristiques.")
        return 1
    print("Aucun motif connu détecté. Cela ne garantit pas l’absence de vulnérabilité.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
