from collections import defaultdict
from typing import Any
from app.analyzers.base import FindingData

# Explicit, maintainable equivalence mapping for confirmed equivalent security rule pairs.
# Bandit is the canonical security owner, so the canonical_rule_id is the bandit:<rule_id>.
CONFIRMED_EQUIVALENT_SECURITY_RULES: dict[str, str] = {
    # Core Bandit / Flake8-Bandit Equivalences
    "bandit:B101": "bandit:B101",
    "ruff:S101":   "bandit:B101",

    "bandit:B102": "bandit:B102",
    "ruff:S102":   "bandit:B102",

    "bandit:B103": "bandit:B103",
    "ruff:S103":   "bandit:B103",

    "bandit:B104": "bandit:B104",
    "ruff:S104":   "bandit:B104",

    "bandit:B105": "bandit:B105",
    "ruff:S105":   "bandit:B105",

    "bandit:B106": "bandit:B106",
    "ruff:S106":   "bandit:B106",

    "bandit:B107": "bandit:B107",
    "ruff:S107":   "bandit:B107",

    "bandit:B108": "bandit:B108",
    "ruff:S108":   "bandit:B108",

    "bandit:B110": "bandit:B110",
    "ruff:S110":   "bandit:B110",

    "bandit:B112": "bandit:B112",
    "ruff:S112":   "bandit:B112",

    "bandit:B113": "bandit:B113",
    "ruff:S113":   "bandit:B113",

    "bandit:B301": "bandit:B301",
    "ruff:S301":   "bandit:B301",

    "bandit:B302": "bandit:B302",
    "ruff:S302":   "bandit:B302",

    "bandit:B303": "bandit:B303",
    "ruff:S303":   "bandit:B303",

    "bandit:B304": "bandit:B304",
    "ruff:S304":   "bandit:B304",

    "bandit:B305": "bandit:B305",
    "ruff:S305":   "bandit:B305",

    "bandit:B306": "bandit:B306",
    "ruff:S306":   "bandit:B306",

    "bandit:B307": "bandit:B307",
    "ruff:S307":   "bandit:B307",

    "bandit:B308": "bandit:B308",
    "ruff:S308":   "bandit:B308",

    "bandit:B310": "bandit:B310",
    "ruff:S310":   "bandit:B310",

    "bandit:B311": "bandit:B311",
    "ruff:S311":   "bandit:B311",

    "bandit:B313": "bandit:B313",
    "ruff:S313":   "bandit:B313",

    "bandit:B314": "bandit:B314",
    "ruff:S314":   "bandit:B314",

    "bandit:B315": "bandit:B315",
    "ruff:S315":   "bandit:B315",

    "bandit:B316": "bandit:B316",
    "ruff:S316":   "bandit:B316",

    "bandit:B317": "bandit:B317",
    "ruff:S317":   "bandit:B317",

    "bandit:B318": "bandit:B318",
    "ruff:S318":   "bandit:B318",

    "bandit:B319": "bandit:B319",
    "ruff:S319":   "bandit:B319",

    "bandit:B320": "bandit:B320",

    "bandit:B324": "bandit:B324",
    "ruff:S324":   "bandit:B324",

    "bandit:B501": "bandit:B501",
    "ruff:S501":   "bandit:B501",

    "bandit:B506": "bandit:B506",
    "ruff:S506":   "bandit:B506",

    "bandit:B601": "bandit:B601",
    "ruff:S601":   "bandit:B601",

    "bandit:B602": "bandit:B602",
    "ruff:S602":   "bandit:B602",

    "bandit:B604": "bandit:B604",
    "ruff:S604":   "bandit:B604",

    "bandit:B605": "bandit:B605",
    "ruff:S605":   "bandit:B605",

    "bandit:B608": "bandit:B608",
    "ruff:S608":   "bandit:B608",

    "bandit:B609": "bandit:B609",
    "ruff:S609":   "bandit:B609",

    "bandit:B610": "bandit:B610",
    "ruff:S610":   "bandit:B610",

    "bandit:B611": "bandit:B611",
    "ruff:S611":   "bandit:B611",

    "bandit:B612": "bandit:B612",
    "ruff:S612":   "bandit:B612",
}

# Designated canonical analyzer priority when duplicate equivalent findings occur
# For security overlaps, Bandit is the canonical security owner
ANALYZER_PRIORITY = {
    "bandit": 1,
    "semgrep": 2,
    "ruff": 3,
    "dependencies": 4,
    "architecture": 5,
    "heuristics": 6,
}


def normalize_file_path(file_path: str) -> str:
    """
    Deterministically normalize file paths so './tests/test_x.py' and 'tests/test_x.py'
    resolve to the exact same path.
    """
    if not file_path:
        return ""
    p = file_path.replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def get_canonical_rule_id(rule_id: str) -> str:
    """
    Get canonical rule ID for equivalent rules.
    If the rule is in CONFIRMED_EQUIVALENT_SECURITY_RULES, return the canonical mapping.
    Otherwise return rule_id as its own canonical identity.
    """
    return CONFIRMED_EQUIVALENT_SECURITY_RULES.get(rule_id, rule_id)


def deduplicate_findings(findings: list[FindingData]) -> list[FindingData]:
    """
    Perform deterministic cross-analyzer deduplication.

    Deduplication identity:
        (normalized_file_path, start_line, canonical_rule_id)

    Rules:
    - Retain ALL findings (preserve analyzer, rule_id, message, evidence, severity).
    - In clusters with equivalent rules from different analyzers, deterministically
      select one primary finding (preferring canonical owner, e.g. Bandit for security).
    - Mark primary finding: is_duplicate = False, primary_finding_id = None.
    - Mark equivalent sibling findings: is_duplicate = True, primary_finding_id = primary.id.
    - Singletons (unique findings) remain: is_duplicate = False, primary_finding_id = None.
    - Different rules on the same file and line remain separate clusters.
    """
    # 1. Normalize paths and assign canonical_rule_id
    for f in findings:
        f.file_path = normalize_file_path(f.file_path)
        f.canonical_rule_id = get_canonical_rule_id(f.rule_id)
        f.is_duplicate = False
        f.primary_finding_id = None

    # 2. Cluster findings by (normalized_path, start_line, canonical_rule_id)
    # Note: If start_line is None (e.g. project-wide analyzer error), do not cluster
    clusters: dict[tuple[str, int | None, str], list[FindingData]] = defaultdict(list)
    unclustered: list[FindingData] = []

    for f in findings:
        if f.start_line is not None and f.canonical_rule_id in CONFIRMED_EQUIVALENT_SECURITY_RULES:
            key = (f.file_path, f.start_line, f.canonical_rule_id)
            clusters[key].append(f)
        else:
            unclustered.append(f)

    processed_findings: list[FindingData] = []

    # 3. Process clusters
    for key, group in clusters.items():
        if len(group) == 1:
            processed_findings.append(group[0])
            continue

        # Sort group by analyzer priority (lowest priority number = canonical owner)
        # Tie-breaker: preserve stable order by id
        group.sort(key=lambda item: (ANALYZER_PRIORITY.get(item.analyzer, 99), item.id))

        primary = group[0]
        primary.is_duplicate = False
        primary.primary_finding_id = None
        processed_findings.append(primary)

        for sibling in group[1:]:
            sibling.is_duplicate = True
            sibling.primary_finding_id = primary.id
            processed_findings.append(sibling)

    # 4. Append unclustered findings
    processed_findings.extend(unclustered)

    return processed_findings
