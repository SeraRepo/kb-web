# Step-by-step — Instancier une LLM Wiki avec Claude Code

Procédure reproductible. Tout ce qui est entre `< >` est à adapter.
Pré-requis : `git`, `claude` (Claude Code), Obsidian, accès réseau pour cloner les repos sources.

## 0. Pré-requis & arborescence de départ

```bash
mkdir <kb-name> && cd <kb-name>
git init
# Place l'idea file à la racine (il sert de brief, pas de config finale)
cp <chemin>/llm-wiki-offensive-ai-security.md ./llm-wiki-template.md
```

Crée seulement le point d'entrée des sources ; le reste de l'arbo sera scaffoldé par Claude Code :

```bash
mkdir -p raw/{papers,repos,guides,frameworks,web,assets}
```

## 1. Cadrer la structure (sans encore ingérer)

Lance Claude Code à la racine du repo, puis :

```
Lis llm-wiki-template.md. C'est le brief de la base de connaissance.
Ne scaffolde rien encore : exécute uniquement l'étape 1 du Bootstrap.
Propose-moi l'ontologie définitive (arbo wiki/, schéma frontmatter,
nesting techniques/ ATLAS oui/non, sous-structure methodologies/),
puis attends ma validation.
```

Tu itères en chat jusqu'à ce que l'ontologie te convienne. **Tu ne valides pas tant
que la taxonomie ne reflète pas ta façon de chercher l'info** (c'est le seul moment
où corriger est gratuit).

## 2. Scaffolder + écrire le CLAUDE.md + le skill ingest

```
Ontologie validée. Exécute les étapes 2 à 4 du Bootstrap :
- scaffolde raw/ et wiki/ (index.md, log.md, overview.md vides, manifest.jsonl vide)
- écris CLAUDE.md en encodant tout le brief (schéma, source handling, ingest/query/lint,
  hardening, règle bilingue, tooling)
- crée le skill `ingest` (commande unique, diff sur manifest.jsonl, idempotent)
Commit chaque étape séparément.
```

Vérifie le résultat :

```bash
git log --oneline
cat CLAUDE.md            # relis-le : c'est lui qui pilote tout le reste
ls .claude/skills/       # ou l'emplacement où le skill a été créé
tree -L 2 wiki/ raw/
```

**Point de contrôle** : si le `CLAUDE.md` ne contient pas la section hardening
(untrusted sources, payloads en blocs inertes, pas de promotion directe
source→instruction), fais-le corriger avant toute ingestion. C'est plus simple de
durcir un repo vide qu'un repo déjà pollué.

## 3. Première ingestion (1 source, supervisée)

Choisis **une** source représentative (un papier ou un repo de doc), pas tout le lot.

```bash
cp <un-papier>.pdf raw/papers/
# ou, pour un repo :
git -C raw/repos clone --depth 1 <url-repo>   # le skill épinglera le commit
```

```
Ingère la nouvelle source dans raw/. Mode supervisé : discute les takeaways
avec moi avant d'écrire, puis montre-moi les pages touchées avant de commit.
```

Contrôle ce que la première ingestion produit, car elle fixe le style de toutes les
suivantes :

```bash
cat wiki/sources/<slug>.md          # provenance présente ? trust: untrusted ?
grep -RIl "atlas:" wiki/techniques/ # les IDs framework sont-ils mappés et vérifiés ?
tail -n 5 wiki/log.md               # entrée de log greppable ?
cat raw/manifest.jsonl              # une ligne avec sha256/commit + derived_pages ?
grep -RIo "\[\[" wiki/ | wc -l      # des wikilinks [[...]] existent ? (pas zéro)
grep -B2 "\[\[" wiki/techniques/*.md | head   # sont-ils INLINE dans le corps,
                                    # ou regroupés sous un titre ## Related/References ?
```

Si quelque chose dévie (IDs inventés, payload en clair dans la prose, page orpheline,
liens regroupés en bas au lieu d'inline, liens markdown `[x](y.md)` au lieu de
`[[x]]`), corrige le `CLAUDE.md` ou le skill **maintenant**, puis re-ingère. Le
linking inline est le point qui casse le plus souvent : vérifie-le dès la première page.

## 4. Ingestion du lot

Une fois le format stabilisé, verse le reste :

```bash
cp <docs>... raw/papers/ raw/guides/
git -C raw/repos clone --depth 1 <url> ...   # un clone par repo
```

```
Ingère toutes les nouvelles sources de raw/.
Tool repos : README + docs/ uniquement.
Doc repos : tous les .md récursivement.
Reste supervisé si je le demande, sinon batch ; commit par source.
```

Ouvre Obsidian sur le dossier `wiki/` en parallèle : suis les wikilinks et la graph
view pendant que Claude Code écrit, c'est ton interface de relecture en temps réel.

## 5. Premier lint

```
Fais une passe de lint : contradictions, pages stale (drift de commit via manifest),
orphelines, cross-refs manquantes, couverture framework (techniques ATLAS/OWASP
sans page, techniques sans mitigation), tools non mappés à une technique.
Propose-moi des sources à chercher, mais ne les fetch pas.
```

## 6. Utiliser la KB au quotidien

Une fois la KB construite, le travail se fait en trois gestes — ingest, query, lint —
qu'on alterne au fil des missions. La règle de fond : **rien d'utile ne reste dans le
chat**. Toute exploration qui produit de la valeur est refilée dans `wiki/` pour que la
connaissance compounde au lieu de se perdre.

### 6.1 Interroger (query)

Tu poses des questions à la KB ; Claude Code lit `index.md`, descend dans les pages
pertinentes, et répond avec citations vers les slugs sources. Quelques requêtes types
selon ton usage :

Préparation de mission (audit/red team) :
```
À partir du wiki, génère une checklist d'audit pour une cible [[rag-system]] :
techniques applicables mappées ATLAS + OWASP LLM, par phase de kill-chain, avec pour
chacune l'outil [[tools/...]] et la mitigation attendue. Format playbook actionnable.
Quand c'est prêt, file-le dans wiki/methodologies/ comme nouvelle page.
```

Veille / synthèse R&D :
```
Quels papiers ingérés depuis 30 jours contredisent ou étendent la page
[[indirect-prompt-injection]] ? Mets à jour la page si besoin et logue l'opération.
```

Matériel de conférence :
```
Produis un deck Marp à partir de [[techniques/...]] et [[targets/agentic-system]] :
8-10 slides, threat model puis 3 techniques avec démo conceptuelle. Sauve en
wiki/decks/ et lie les pages sources.
```

Préparation d'offre client (scoping d'audit IA) :
```
Un client expose un système [[mcp-server]] + [[rag-system]]. À partir du wiki,
rédige la section méthodologie d'une offre : surface d'attaque par composant,
techniques ATLAS couvertes, livrables. EN, ton commercial mais technique.
```

**File-back systématique.** Un comparatif, un playbook, un extrait de méthodo : si
c'est réutilisable, demande explicitement de le filer (`file-le dans wiki/...`). Sinon
il faudra le reconstruire à la prochaine mission — exactement ce que ce système est
censé éliminer.

### 6.2 Ingérer en continu (ingest)

Le geste reste le même que pendant la construction : tu déposes dans `raw/`, tu lances
l'ingestion en une commande.
```bash
cp <nouveau-papier>.pdf raw/papers/
git -C raw/repos clone --depth 1 <url>
```
```
Ingère les nouvelles sources de raw/. Respecte les linking conventions
(wikilinks inline), mappe les IDs framework, mets à jour index.md et log.md.
```
Garde Obsidian ouvert sur `wiki/` : tu relis les diffs via la graph view en temps réel
pendant que Claude Code écrit.

### 6.3 Maintenir (lint)

Périodiquement, ou avant un livrable important :
```
Passe de lint : contradictions, pages stale (drift de commit), orphelines,
liens regroupés en bas au lieu d'inline, couverture framework (techniques ATLAS/OWASP
sans page, techniques sans mitigation, tools non mappés). Propose des sources à
chercher sans les fetch.
```
Le lint est aussi ton générateur de questions : les trous qu'il remonte (technique non
couverte, mitigation manquante) sont autant de pistes pour la prochaine ingestion ou la
prochaine recherche de sources.

### 6.4 Naviguer côté humain (Obsidian)

Obsidian est ta couche de lecture : graph view pour voir les hubs et les orphelines,
backlinks pour remonter d'une technique à tout ce qui la référence, recherche full-text
pour les requêtes triviales que tu ne veux pas passer par l'agent. La graph view est
aussi ton contrôle qualité visuel : si une page reste isolée, c'est un défaut de
linking à corriger (cf. §6.3).

## 7. Versioning & hygiène

```bash
echo "raw/repos/" >> .gitignore   # optionnel : ne pas versionner les clones lourds ;
                                  # le manifest garde origin + commit pour rejouer
git add -A && git commit -m "wiki: <résumé>"   # si le skill ne commit pas lui-même
```

Décision à trancher : versionner `raw/` (reproductibilité totale, repo lourd) ou ne
versionner que `wiki/` + `manifest.jsonl` (repo léger, sources rejouables via le
manifest). Le manifest rend la seconde option viable.

Le repo wiki étant du git, tu hérites gratuitement de l'historique, des branches (utile
pour tester une réorganisation d'ontologie sans casser l'existant) et du `git revert`
si une ingestion empoisonnée a glissé une entrée à corriger (cf. provenance par claim).

---

## Réutiliser ce setup dans un autre domaine

La procédure ci-dessus est **invariante au domaine**. Seul l'idea file change. Pour
un nouveau domaine (audit mobile, dev de solutions LLM, etc.) :

1. Pars du gabarit `llm-wiki-template.md` (fourni à part).
2. Remplis les blocs `<<...>>` (domaine, référentiels, ontologie, types liables,
   source handling, formats de sortie, hardening) — deux exemples remplis sont fournis
   en fin de gabarit.
3. Sauve-le en `llm-wiki-template.md` dans un nouveau repo et reprends à l'étape 0.

Le reste — trois couches, ingest/query/lint, index.md/log.md, skill d'ingestion,
linking conventions, règle bilingue, tooling — ne bouge pas.