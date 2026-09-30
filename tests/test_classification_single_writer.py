"""
Only the classifier writes classification_type / is_ot during capture.

Every module under scrutics/ is parsed and scanned for assignments to an attribute named
classification_type or is_ot, setattr calls with those names, and keyword arguments with
those names. An AST scan is used instead of grep so comments and strings are ignored and
keyword arguments and setattr are caught. The allowed writers are the classifier, the Asset
model's own constructor and is_ot setter, and restoring a saved session.
"""

import ast
from pathlib import Path

import scrutics

NAMES = {"classification_type", "is_ot"}

ALLOWED = {
    ("classifier/asset_classifier.py", "classify_asset"),
    ("db/inventory.py", "Asset.__post_init__"),
    ("db/inventory.py", "Asset.is_ot"),
    ("ui/tui.py", "ScruticsApp._load_last_results"),
}


class _WriterFinder(ast.NodeVisitor):
    def __init__(self):
        self.scope = []
        self.writes = []

    def _visit_scope(self, node):
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    visit_ClassDef = visit_FunctionDef = visit_AsyncFunctionDef = _visit_scope

    def _record(self, node, what):
        self.writes.append((".".join(self.scope), node.lineno, what))

    def _check_target(self, target):
        if isinstance(target, ast.Attribute) and target.attr in NAMES:
            self._record(target, f"assignment to .{target.attr}")
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._check_target(element)

    def visit_Assign(self, node):
        for target in node.targets:
            self._check_target(target)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        self._check_target(node.target)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        self._check_target(node.target)
        self.generic_visit(node)

    def visit_Call(self, node):
        for kw in node.keywords:
            if kw.arg in NAMES:
                self._record(node, f"keyword argument {kw.arg}=")
        if (isinstance(node.func, ast.Name) and node.func.id == "setattr" and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant) and node.args[1].value in NAMES):
            self._record(node, f"setattr {node.args[1].value}")
        self.generic_visit(node)


def _allowed_entry(rel, scope):
    for path, allowed in ALLOWED:
        if rel == path and (scope == allowed or scope.startswith(allowed + ".")):
            return (path, allowed)
    return None


def test_only_the_classifier_and_session_loading_write_classification():
    root = Path(scrutics.__file__).parent
    violations = []
    seen_allowed = set()
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        finder = _WriterFinder()
        finder.visit(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
        for scope, line, what in finder.writes:
            entry = _allowed_entry(rel, scope)
            if entry:
                seen_allowed.add(entry)
            else:
                violations.append(f"{rel}:{line} in {scope or '<module>'}: {what}")
    assert violations == []
    # Every allowed writer must still exist, so the allowlist cannot silently go stale
    assert seen_allowed == ALLOWED
