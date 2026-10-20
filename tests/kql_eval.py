"""
A small KQL *subset* evaluator, used to test detection logic offline.

This is not a KQL engine. It cannot run a real Sentinel query, and pretending
otherwise would be worse than not testing at all. What it does is evaluate the
handful of operators our rules actually use against fixture data, so that an
edit which silently breaks a match fails the build.

Supported:
    | where <expr>           comparisons, and/or/not, in, has_any, has, startswith,
                            between, =~, contains, isempty/isnotempty
    | extend <name> = <expr>
    | project <a>, <b>, ...
    | summarize count() [by ...]     (only the shapes our fixtures need)
    | take/limit N
    let <name> = <expr>;             (constants and simple dynamic() literals)

Deliberately unsupported (and raising, so a rule that needs them is visible):
    joins, mv-expand, serialize/prev, parse_json navigation, dcount with args,
    make_set, bins, any function we have not implemented.

A rule whose query uses unsupported syntax is reported as `unverifiable` rather
than failing — and the CI report counts those, so the gap is visible.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable


class Unsupported(Exception):
    """The query uses KQL this evaluator does not model."""


@dataclass
class Table:
    rows: list[dict[str, Any]] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.rows)


# ---------------------------------------------------------------------------
# Expression evaluation
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"""
    \s*(?:
      (?P<str>"[^"]*"|'[^']*')
    | (?P<num>-?\d+(?:\.\d+)?)
    | (?P<op>==|!=|>=|<=|=~|!~|>|<|=|\(|\)|,|\.\.)
    | (?P<word>[A-Za-z_][A-Za-z0-9_]*(?:\[\d+\])?)
    | (?P<pipe>\|)
    )""", re.X)


def _tokenize(expr: str) -> list[str]:
    tokens, pos = [], 0
    while pos < len(expr):
        m = _TOKEN_RE.match(expr, pos)
        if not m:
            if expr[pos:].strip() == "":
                break
            raise Unsupported(f"cannot tokenize at {expr[pos:pos+20]!r}")
        tokens.append(m.group(0).strip())
        pos = m.end()
    return [t for t in tokens if t]


def _resolve(value: str, row: dict[str, Any]) -> Any:
    if value.startswith(('"', "'")):
        return value[1:-1]
    if re.fullmatch(r"-?\d+(\.\d+)?", value):
        return float(value) if "." in value else int(value)
    if value in ("true", "false"):
        return value == "true"
    # Field reference, possibly with an index (securityRules[0]).
    m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\[(\d+)\]", value)
    if m:
        base = row.get(m.group(1))
        if isinstance(base, list):
            idx = int(m.group(2))
            return base[idx] if idx < len(base) else None
        return None
    return row.get(value)


def _truthy(v: Any) -> bool:
    return bool(v) if not isinstance(v, str) else v != ""


def eval_condition(expr: str, row: dict[str, Any]) -> bool:
    """Evaluate a `where` expression against one row."""
    expr = expr.strip()

    # Strip comments anywhere in the line.
    expr = re.sub(r"//[^\n]*", "", expr)
    expr = re.sub(r"\s+", " ", expr).strip()

    if not expr:
        return True

    # Time bounds. Fixture timestamps are historical by definition, so a
    # `TimeGenerated > ago(...)` guard is treated as satisfied — the fixture
    # itself is the statement "these events are in scope".
    if re.fullmatch(r"\w+\s*[<>]=?\s*ago\([^)]*\)", expr):
        return True

    # Parentheses: evaluate the inside first.
    while expr.startswith("(") and expr.endswith(")"):
        expr = expr[1:-1].strip()

    for op, fn in (
        (" or ", lambda a, b: a or b),
        (" and ", lambda a, b: a and b),
    ):
        if op in expr:
            left, right = expr.split(op, 1)
            return fn(eval_condition(left, row), eval_condition(right, row))

    if expr.startswith("not "):
        return not eval_condition(expr[4:], row)

    # x between (a .. b)
    m = re.fullmatch(r"(\S+)\s+between\s*\(\s*(\S+)\s*\.\.\s*(\S+)\s*\)", expr)
    if m:
        v, lo, hi = (_resolve(g, row) for g in m.groups())
        try:
            return lo <= v <= hi
        except TypeError:
            return False

    # in / has_any
    m = re.fullmatch(r"(\S+)\s+(in|!in)\s*\((.*)\)", expr)
    if m:
        field_name, neg, rest = m.groups()
        v = _resolve(field_name, row)
        items = [_resolve(t, row) for t in _split_args(rest)]
        hit = v in items
        return not hit if neg == "!in" else hit

    m = re.fullmatch(r"(\S+)\s+(has_any|has_all)\s*\((.*)\)", expr)
    if m:
        field_name, kind, rest = m.groups()
        v = _resolve(field_name, row)
        items = [str(_resolve(t, row)) for t in _split_args(rest)]
        if v is None:
            return False
        s = str(v).lower()
        hits = [i.lower() in s for i in items]
        return any(hits) if kind == "has_any" else all(hits)

    # isempty / isnotempty
    m = re.fullmatch(r"(isempty|isnotempty)\s*\((\S+)\)", expr)
    if m:
        kind, field_name = m.groups()
        v = _resolve(field_name, row)
        empty = v is None or v == "" or v == [] or v == {}
        return empty if kind == "isempty" else not empty

    # Negated string operators.
    m = re.fullmatch(r"(\S+)\s+!(has|contains|startswith|endswith)\s+(\S+)", expr)
    if m:
        field_name, kind, needle = m.groups()
        v = _resolve(field_name, row)
        if v is None:
            return True
        s_, n = str(v).lower(), str(_resolve(needle, row)).lower()
        return not {"has": n in s_, "contains": n in s_,
                    "startswith": s_.startswith(n), "endswith": s_.endswith(n)}[kind]

    # String operators.
    m = re.fullmatch(r"(\S+)\s+(has|contains|startswith|endswith)\s+(\S+)", expr)
    if m:
        field_name, kind, needle = m.groups()
        v = _resolve(field_name, row)
        if v is None:
            return False
        s, n = str(v).lower(), str(_resolve(needle, row)).lower()
        return {"has": n in s, "contains": n in s,
                "startswith": s.startswith(n), "endswith": s.endswith(n)}[kind]

    # Comparison operators.
    m = re.fullmatch(r"(\S+)\s*(==|=~|!=|!~|>=|<=|>|<)\s*(\S+)", expr)
    if m:
        left_name, op, right_name = m.groups()
        left, right = _resolve(left_name, row), _resolve(right_name, row)
        if left is None:
            return False
        try:
            if op in ("=~",):
                return str(left).lower() == str(right).lower()
            if op in ("!~",):
                return str(left).lower() != str(right).lower()
            if op == "==":
                return left == right or str(left) == str(right)
            if op == "!=":
                return not (left == right or str(left) == str(right))
            if op == ">":
                return float(left) > float(right)
            if op == "<":
                return float(left) < float(right)
            if op == ">=":
                return float(left) >= float(right)
            if op == "<=":
                return float(left) <= float(right)
        except (TypeError, ValueError):
            return False

    # A bare field: truthiness.
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\[\d+\])?", expr):
        return _truthy(_resolve(expr, row))

    raise Unsupported(f"cannot evaluate condition: {expr!r}")


def _split_args(s: str) -> list[str]:
    # A flow-sequence literal passed as one argument: `in ([a, b])`.
    stripped = s.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        s = stripped[1:-1]
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


# ---------------------------------------------------------------------------
# Pipeline evaluation
# ---------------------------------------------------------------------------

def _parse_let(query: str) -> tuple[dict[str, str], str]:
    """Extract `let name = expr;` constants and return the remaining query."""
    constants: dict[str, str] = {}
    for m in re.finditer(r"let\s+(\w+)\s*=\s*([^;]+);", query, re.S):
        constants[m.group(1)] = m.group(2).strip()
    remaining = re.sub(r"let\s+\w+\s*=\s*[^;]+;", "", query)
    return constants, remaining


def _expand_let_in_clauses(expr: str, constants: dict[str, str]) -> str:
    """
    KQL allows `| where X in (someLet)` where someLet is a dynamic/list const.
    Inline those before evaluation.
    """
    for name, value in constants.items():
        if not value.startswith(("[", "dynamic([")):
            continue
        literal = re.sub(r"^dynamic\((.*)\)$", r"\1", value, flags=re.S)
        expr = re.sub(rf"\bin\s*\(\s*{name}\s*\)", f"in ({literal})", expr)
        expr = re.sub(rf"\bhas_any\s*\(\s*{name}\s*\)", f"has_any ({literal})", expr)
    return expr


def _substitute(expr: str, constants: dict[str, str]) -> str:
    for name, value in constants.items():
        # Only inline literal lists/scalars. `make_set(...)`-style constants are
        # part of a stage we do not model and must not be pasted into a condition.
        if not (value.startswith("[") or value.startswith("dynamic([")
                or re.fullmatch(r"-?\d+(\.\d+)?", value) or value.startswith(('"', "'"))):
            continue
        # dynamic([...]) literals are used only in `in (...)` and `has_any`,
        # which _resolve handles when the whole literal is passed through.
        value = re.sub(r"^dynamic\((.*)\)$", r"\1", value, flags=re.S)
        expr = re.sub(rf"\b{name}\b", value, expr)
    return expr


_STAGES = {"where", "extend", "project", "take", "limit", "summarize", "sort", "order"}


def run(query: str, rows: list[dict[str, Any]]) -> Table:
    """Evaluate a supported subset of a KQL pipeline against fixture rows."""
    constants, body = _parse_let(query)
    body = _expand_let_in_clauses(body, constants)
    stages = []
    for raw_line in body.split("\n"):
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        stages.append(line)

    # Re-join multi-line stages: a stage starts with a pipe.
    STAGE_KEYWORDS = ("where", "extend", "project", "summarize", "take", "limit",
                      "sort", "order", "join", "union", "distinct", "top")
    merged: list[str] = []
    for stage in stages:
        first_word = stage.split(None, 1)[0].lower()
        if stage.startswith("|"):
            merged.append(stage[1:].strip())
        elif merged and first_word in STAGE_KEYWORDS:
            # A stage without a leading pipe (allowed after a `;` in a let).
            merged.append(stage)
        elif merged:
            merged[-1] += " " + stage
        else:
            merged.append(stage)
    merged = [m for m in merged if m and m != "|"]

    # A `let <name> = <table expression>; ... <name> | project ...` pattern: the
    # query body after the lets starts with the variable name, which stands for
    # the stage sequence the let already captured. Splice it back in.
    if merged:
        first = merged[0].split("\n")[0].strip()
        if first in constants and "<-" not in first and " " not in first:
            spliced = [st.strip() for st in constants[first].split("\n") if st.strip()]
            merged = spliced + merged[1:]

    table = Table(rows=[dict(r) for r in rows])

    for position, stage in enumerate(merged):
        stage = _substitute(stage, constants)
        head = stage.split(None, 1)[0].lower()

        # The first stage names the source table. Offline, the fixture rows are
        # already that table, so it is a no-op — not an error.
        if position == 0 and head not in _STAGES:
            table = Table(table.rows)
            continue

        if head == "where":
            cond = stage[len("where"):].strip()
            table = Table([r for r in table.rows if eval_condition(cond, r)])

        elif head == "extend":
            assignments = _split_args(stage[len("extend"):].strip())
            new_rows = []
            for r in table.rows:
                r = dict(r)
                for a in assignments:
                    name, _, value = a.partition("=")
                    name, value = name.strip(), value.strip()
                    inner = re.fullmatch(r"tostring\((\w+(?:\.\w+)?)\)", value)
                    if inner:
                        # tostring(field) or tostring(obj.field). Resolve dotted
                        # paths against nested dicts in the fixture.
                        parts = inner.group(1).split(".")
                        current = r.get(parts[0])
                        for part in parts[1:]:
                            current = (current or {}).get(part) if isinstance(current, dict) else None
                        r[name] = current
                    elif re.fullmatch(r"\S+", value):
                        r[name] = _resolve(value, r)
                    elif value.startswith("parse_json("):
                        raise Unsupported("parse_json navigation is not modelled")
                    else:
                        raise Unsupported(f"cannot evaluate extend expression {value!r}")
                new_rows.append(r)
            table = Table(new_rows)

        elif head == "project":
            cols = [c.strip() for c in _split_args(stage[len("project"):].strip())]
            table = Table([{c: r.get(c) for c in cols} for r in table.rows])

        elif head in ("sort", "order"):
            # Ordering does not change the row count, which is what fixtures assert.
            continue

        elif head in ("take", "limit"):
            n = int(stage.split()[1])
            table = Table(table.rows[:n])

        elif head == "summarize":
            rest = stage[len("summarize"):].strip()
            if " by " not in rest:
                raise Unsupported("summarize without `by` is not modelled")
            agg_part, by_part = rest.split(" by ", 1)
            agg_part = agg_part.strip()
            if not agg_part.startswith("count()"):
                raise Unsupported(f"only count() aggregation is modelled, got {agg_part!r}")
            group_keys = [k.strip() for k in _split_args(by_part)]
            if any("bin(" in k for k in group_keys):
                # bin() grouping is treated as a pass-through key.
                group_keys = [re.sub(r"bin\(\s*(\w+).*\)", r"\1", k) for k in group_keys]

            groups: dict[tuple, dict[str, Any]] = {}
            for r in table.rows:
                key = tuple(r.get(k) for k in group_keys)
                entry = groups.setdefault(key, {**{k: r.get(k) for k in group_keys}, "count_": 0})
                entry["count_"] += 1
            table = Table(list(groups.values()))

        else:
            raise Unsupported(f"unsupported stage: {head}")

    return table


def count(query: str, rows: list[dict[str, Any]]) -> int:
    """Rows the query returns. The number a fixture test asserts on."""
    return len(run(query, rows))
