import ast
from pathlib import Path
from typing import Any
import networkx as nx
from app.analyzers.base import BaseAnalyzer, FindingData, extract_snippet


class ArchitectureAnalyzer(BaseAnalyzer):
    default_category = "architecture"
    analyzer_name = "architecture"

    def __init__(self, workspace_root: Path):
        super().__init__(workspace_root)
        self.metrics_data: list[dict[str, Any]] = []

    def _file_to_module(self, file_path: Path) -> str:
        """Convert a file path to a Python dot-separated module name."""
        rel = file_path.relative_to(self.workspace_root)
        parts = list(rel.parts)
        if parts[-1].endswith(".py"):
            parts[-1] = parts[-1][:-3]
        if parts[-1] == "__init__":
            parts = parts[:-1]
        return ".".join(parts) if parts else "root"

    def run(self) -> list[FindingData]:
        findings: list[FindingData] = []
        self.metrics_data = []

        python_files = [
            p for p in self.workspace_root.rglob("*.py")
            if ".git" not in p.parts and "node_modules" not in p.parts and ".venv" not in p.parts
        ]

        if not python_files:
            return findings

        # Map file paths to module names
        file_to_mod: dict[Path, str] = {}
        mod_to_file: dict[str, Path] = {}
        for p in python_files:
            mod_name = self._file_to_module(p)
            file_to_mod[p] = mod_name
            mod_to_file[mod_name] = p

        all_modules = set(file_to_mod.values())

        # Build directed graph
        graph = nx.DiGraph()
        for mod in all_modules:
            graph.add_node(mod)

        # Parse ASTs
        for py_file in python_files:
            src_mod = file_to_mod[py_file]
            try:
                with open(py_file, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                tree = ast.parse(content, filename=str(py_file))
            except SyntaxError as e:
                findings.append(
                    FindingData(
                        analyzer="architecture",
                        category="quality",
                        severity="medium",
                        rule_id="arch:syntax-error",
                        file_path=str(py_file.relative_to(self.workspace_root)).replace("\\", "/"),
                        start_line=e.lineno or 1,
                        end_line=e.lineno or 1,
                        message=f"Syntax error while parsing AST: {e.msg}",
                        evidence={"lineno": e.lineno, "offset": e.offset},
                    )
                )
                continue
            except Exception as e:
                findings.append(
                    self.create_error_finding(f"Failed to parse {py_file.name}: {e}")
                )
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imported = alias.name
                        # Check if imported is an internal module or prefix
                        for candidate in all_modules:
                            if imported == candidate or candidate.startswith(f"{imported}."):
                                graph.add_edge(src_mod, candidate)
                elif isinstance(node, ast.ImportFrom):
                    level = node.level
                    base_module = node.module or ""
                    target_module = ""
                    if level > 0:
                        # Relative import
                        current_parts = src_mod.split(".")
                        if level <= len(current_parts):
                            prefix = ".".join(current_parts[:-level])
                            target_module = f"{prefix}.{base_module}".strip(".") if prefix else base_module
                    else:
                        target_module = base_module

                    if target_module:
                        for candidate in all_modules:
                            if target_module == candidate or candidate.startswith(f"{target_module}."):
                                graph.add_edge(src_mod, candidate)

        # Detect Strongly Connected Components (cycles)
        sccs = [list(c) for c in nx.strongly_connected_components(graph) if len(c) > 1]
        cycle_mod_map: dict[str, int] = {}
        for idx, scc in enumerate(sccs, start=1):
            for mod in scc:
                cycle_mod_map[mod] = idx

            # Add finding for each circular group
            sample_file = mod_to_file.get(scc[0])
            rel_file = (
                str(sample_file.relative_to(self.workspace_root)).replace("\\", "/")
                if sample_file else "."
            )
            findings.append(
                FindingData(
                    analyzer="architecture",
                    category="architecture",
                    severity="high",
                    rule_id="arch:circular-dependency",
                    file_path=rel_file,
                    start_line=1,
                    end_line=1,
                    message=f"Circular dependency cycle detected between modules: {', '.join(scc[:5])}{'...' if len(scc) > 5 else ''}",
                    evidence={"cycle_component_id": idx, "modules": scc},
                    redacted_snippet=f"# Circular dependency cycle component {idx}\n# Modules: {scc}",
                )
            )

        # Calculate metrics for each module
        for mod in sorted(all_modules):
            fan_in = graph.in_degree(mod)
            fan_out = graph.out_degree(mod)
            comp_id = cycle_mod_map.get(mod)

            self.metrics_data.append({
                "module": mod,
                "fan_in": fan_in,
                "fan_out": fan_out,
                "circular_component_id": comp_id,
            })

            # Check for architecture hubs (high coupling)
            if fan_out >= 10:
                mod_file = mod_to_file.get(mod)
                rel_file = (
                    str(mod_file.relative_to(self.workspace_root)).replace("\\", "/")
                    if mod_file else "."
                )
                findings.append(
                    FindingData(
                        analyzer="architecture",
                        category="architecture",
                        severity="medium",
                        rule_id="arch:high-coupling-hub",
                        file_path=rel_file,
                        start_line=1,
                        end_line=1,
                        message=f"Module '{mod}' is a high-coupling hub with {fan_out} outgoing dependencies.",
                        evidence={"module": mod, "fan_in": fan_in, "fan_out": fan_out},
                        redacted_snippet=f"# High coupling hub: {mod} (fan_out={fan_out}, fan_in={fan_in})",
                    )
                )

        return findings
