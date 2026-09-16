from typing import Any
from app.analyzers.base import FindingData
from app.scoring.rules import SEVERITY_PENALTIES, DIMENSION_WEIGHTS, CATEGORY_TO_DIMENSION


class ScoreCalculator:
    @staticmethod
    def calculate(
        findings: list[FindingData],
        architecture_metrics: list[dict[str, Any]] | None = None,
    ) -> tuple[dict[str, float], dict[str, Any]]:
        """
        Compute deterministic scores and detailed audit breakdown.
        Returns:
            (dimension_scores_dict, full_audit_breakdown_dict)
        """
        # Initialize breakdown data structure
        dimensions = [
            "security",
            "architecture",
            "maintainability",
            "performance",
            "code_quality",
            "dependencies",
        ]

        breakdown: dict[str, Any] = {
            dim: {
                "starting_score": 100.0,
                "penalties": [],
                "total_penalty": 0.0,
                "final_score": 100.0,
                "weight": DIMENSION_WEIGHTS[dim],
            }
            for dim in dimensions
        }

        # Process finding penalties
        for f in findings:
            # Ignore duplicate findings from secondary analyzers
            if getattr(f, "is_duplicate", False):
                continue

            dim = CATEGORY_TO_DIMENSION.get(f.category, "code_quality")
            penalty_val = SEVERITY_PENALTIES.get(f.severity.lower(), 0.0)

            if penalty_val > 0:
                breakdown[dim]["penalties"].append({
                    "finding_id": f.id,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "penalty": penalty_val,
                    "file_path": f.file_path,
                    "start_line": f.start_line,
                    "message": f.message,
                })
                breakdown[dim]["total_penalty"] += penalty_val

        # Check performance dimension specifically
        perf_data = breakdown["performance"]
        if len(perf_data["penalties"]) == 0:
            perf_data["status"] = "neutral"
            perf_data["explanation"] = (
                "No static performance issues were detected by the implemented rules."
            )
        else:
            perf_data["status"] = "penalized"
            perf_data["explanation"] = f"{len(perf_data['penalties'])} static performance findings detected."

        # Compute dimension scores with floor at 0.0
        scores: dict[str, float] = {}
        for dim in dimensions:
            raw_score = 100.0 - breakdown[dim]["total_penalty"]
            final_score = max(0.0, round(raw_score, 1))
            breakdown[dim]["final_score"] = final_score
            scores[dim] = final_score

        # Compute overall score
        overall = (
            scores["security"] * DIMENSION_WEIGHTS["security"]
            + scores["architecture"] * DIMENSION_WEIGHTS["architecture"]
            + scores["maintainability"] * DIMENSION_WEIGHTS["maintainability"]
            + scores["performance"] * DIMENSION_WEIGHTS["performance"]
            + scores["code_quality"] * DIMENSION_WEIGHTS["code_quality"]
            + scores["dependencies"] * DIMENSION_WEIGHTS["dependencies"]
        )
        overall = round(overall, 1)
        scores["overall"] = overall

        # Add overall calculation audit
        breakdown["overall"] = {
            "formula": (
                "0.25*(Security) + 0.15*(Architecture) + 0.15*(Maintainability) "
                "+ 0.10*(Performance) + 0.20*(CodeQuality) + 0.15*(Dependencies)"
            ),
            "inputs": {dim: scores[dim] for dim in dimensions},
            "weights": DIMENSION_WEIGHTS,
            "calculated_overall": overall,
        }

        return scores, breakdown
