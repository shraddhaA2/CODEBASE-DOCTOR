from typing import Literal

# Severity penalties per specification
SEVERITY_PENALTIES: dict[str, float] = {
    "critical": 20.0,
    "high": 8.0,
    "medium": 3.0,
    "low": 1.0,
    "info": 0.0,
}

# Dimension weights summing to 1.0
DIMENSION_WEIGHTS: dict[str, float] = {
    "security": 0.25,
    "architecture": 0.15,
    "maintainability": 0.15,
    "performance": 0.10,
    "code_quality": 0.20,
    "dependencies": 0.15,
}

# Category to dimension mapping
CATEGORY_TO_DIMENSION: dict[str, str] = {
    "security": "security",
    "architecture": "architecture",
    "dead_code": "maintainability",
    "bug": "code_quality",
    "quality": "code_quality",
    "dependency": "dependencies",
    "performance": "performance",
}
