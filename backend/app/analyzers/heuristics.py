import ast
from pathlib import Path
from app.analyzers.base import BaseAnalyzer, FindingData, extract_snippet


class HeuristicsAnalyzer(BaseAnalyzer):
    default_category = "quality"
    analyzer_name = "heuristics"

    def run(self) -> list[FindingData]:
        findings: list[FindingData] = []

        python_files = [
            p for p in self.workspace_root.rglob("*.py")
            if ".git" not in p.parts and "node_modules" not in p.parts and ".venv" not in p.parts
        ]

        if not python_files:
            return findings

        # First pass: collect all function calls across all files to assist dead-code heuristic
        all_called_names = set()
        file_ast_cache: dict[Path, ast.AST] = {}

        for py_file in python_files:
            try:
                with open(py_file, "r", encoding="utf-8", errors="replace") as f:
                    tree = ast.parse(f.read(), filename=str(py_file))
                file_ast_cache[py_file] = tree
                for node in ast.walk(tree):
                    if isinstance(node, ast.Name):
                        all_called_names.add(node.id)
                    elif isinstance(node, ast.Attribute):
                        all_called_names.add(node.attr)
            except Exception:
                continue

        # Second pass: check heuristics on each AST
        for py_file, tree in file_ast_cache.items():
            rel_path = str(py_file.relative_to(self.workspace_root)).replace("\\", "/")

            for node in ast.walk(tree):
                # 1. Suspicious infinite loop: while True / 1 without break/return/raise
                if isinstance(node, ast.While):
                    is_const_true = (
                        (isinstance(node.test, ast.Constant) and bool(node.test.value) is True)
                        or (isinstance(node.test, ast.NameConstant) and node.test.value is True)  # python < 3.8
                    )
                    if is_const_true:
                        has_exit = False
                        for subnode in ast.walk(node):
                            if isinstance(subnode, (ast.Break, ast.Return, ast.Raise)):
                                has_exit = True
                                break
                        if not has_exit:
                            line = node.lineno
                            snippet = extract_snippet(self.workspace_root, rel_path, line, line + 3)
                            findings.append(
                                FindingData(
                                    analyzer="heuristics",
                                    category="bug",
                                    severity="high",
                                    rule_id="heuristic:infinite-loop",
                                    file_path=rel_path,
                                    start_line=line,
                                    end_line=line,
                                    message="Suspicious infinite loop detected by static heuristic: 'while True' loop contains no break, return, or raise statements.",
                                    evidence={"confidence": 0.85, "heuristic": "infinite_loop_without_exit"},
                                    redacted_snippet=snippet,
                                )
                            )

                # 2. Broad exception suppression: bare except or except Exception: pass
                elif isinstance(node, ast.ExceptHandler):
                    is_bare = node.type is None
                    is_generic_exception = (
                        isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"}
                    )
                    is_silent_pass = (
                        len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
                    )

                    if (is_bare or is_generic_exception) and is_silent_pass:
                        line = node.lineno
                        snippet = extract_snippet(self.workspace_root, rel_path, line, line + 2)
                        findings.append(
                            FindingData(
                                analyzer="heuristics",
                                category="quality",
                                severity="medium",
                                rule_id="heuristic:broad-exception-suppression",
                                file_path=rel_path,
                                start_line=line,
                                end_line=line,
                                message="Broad exception suppression detected by static heuristic: 'except Exception: pass' or bare 'except:' silences unexpected runtime failures.",
                                evidence={"confidence": 0.95, "heuristic": "silent_exception_suppression"},
                                redacted_snippet=snippet,
                            )
                        )

                # 3. Resource opened without context manager: var = open(...) outside With
                elif isinstance(node, ast.Assign):
                    if isinstance(node.value, ast.Call):
                        func = node.value.func
                        func_name = ""
                        if isinstance(func, ast.Name):
                            func_name = func.id
                        elif isinstance(func, ast.Attribute):
                            func_name = func.attr

                        if func_name in {"open", "socket"}:
                            line = node.lineno
                            snippet = extract_snippet(self.workspace_root, rel_path, line, line)
                            findings.append(
                                FindingData(
                                    analyzer="heuristics",
                                    category="quality",
                                    severity="low",
                                    rule_id="heuristic:missing-context-manager",
                                    file_path=rel_path,
                                    start_line=line,
                                    end_line=line,
                                    message=f"Resource '{func_name}' allocated without a context manager detected by static heuristic. Consider using 'with {func_name}(...)' to prevent resource leaks.",
                                    evidence={"confidence": 0.80, "heuristic": "resource_without_context_manager"},
                                    redacted_snippet=snippet,
                                )
                            )

                # 4. Possible None dereference:
                # Pattern: x = obj.get(...) or obj.find(...); followed immediately by x.attr or x[...]
                # We inspect function/method bodies
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    assigned_none_candidates: dict[str, int] = {}
                    for stmt in node.body:
                        if isinstance(stmt, ast.Assign):
                            if isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Attribute):
                                method_name = stmt.value.func.attr
                                if method_name in {"get", "find", "search", "lookup"}:
                                    for target in stmt.targets:
                                        if isinstance(target, ast.Name):
                                            assigned_none_candidates[target.id] = stmt.lineno
                        elif isinstance(stmt, (ast.Expr, ast.Return)):
                            # Check if value dereferences any candidate
                            for subnode in ast.walk(stmt):
                                if isinstance(subnode, ast.Attribute) and isinstance(subnode.value, ast.Name):
                                    var_name = subnode.value.id
                                    if var_name in assigned_none_candidates:
                                        line = subnode.lineno
                                        snippet = extract_snippet(self.workspace_root, rel_path, line - 1, line + 1)
                                        findings.append(
                                            FindingData(
                                                analyzer="heuristics",
                                                category="bug",
                                                severity="medium",
                                                rule_id="heuristic:possible-none-dereference",
                                                file_path=rel_path,
                                                start_line=line,
                                                end_line=line,
                                                message=f"Possible None dereference detected by static heuristic: '{var_name}' assigned from '{assigned_none_candidates[var_name]}' call may be None when attribute '{subnode.attr}' is accessed.",
                                                evidence={"confidence": 0.70, "variable": var_name, "heuristic": "possible_none_deref"},
                                                redacted_snippet=snippet,
                                            )
                                        )
                                        assigned_none_candidates.pop(var_name, None)

                # 5. Potentially dead private/internal functions
                if isinstance(node, ast.FunctionDef):
                    fn_name = node.name
                    # Private internal helper not starting with double underscore (dunder)
                    if fn_name.startswith("_") and not fn_name.startswith("__") and len(fn_name) > 2:
                        # Count occurrences in all_called_names
                        # If only occurs 1 time or 0 times (definition itself)
                        occurrences = sum(1 for name in all_called_names if name == fn_name)
                        if occurrences <= 1:
                            line = node.lineno
                            snippet = extract_snippet(self.workspace_root, rel_path, line, line + 3)
                            findings.append(
                                FindingData(
                                    analyzer="heuristics",
                                    category="dead_code",
                                    severity="low",
                                    rule_id="heuristic:dead-function",
                                    file_path=rel_path,
                                    start_line=line,
                                    end_line=line,
                                    message=f"Potential unused internal function detected by static heuristic: '{fn_name}' is defined but does not appear to be invoked.",
                                    evidence={"confidence": 0.75, "function": fn_name, "heuristic": "uncalled_internal_function"},
                                    redacted_snippet=snippet,
                                )
                            )

        return findings
