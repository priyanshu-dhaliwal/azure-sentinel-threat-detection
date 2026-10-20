"""
A deliberately small YAML subset parser.

PyYAML needs a C extension to build on this machine, and the CI image has it —
but the rules must also be testable on a plain Python install. Rather than pin a
dependency that cannot build everywhere, this module parses exactly the YAML the
rule files use:

  * mappings by indentation
  * block scalars  (`|` and `>`)
  * flow sequences (`[a, b]`)
  * lists of scalars (`- x`) and lists of mappings (`- key: value`)
  * plain scalars, quoted strings, booleans, ints

Anything outside that raises YamlUnsupported, which surfaces in the test output
instead of silently producing a wrong structure.
"""

from __future__ import annotations

from typing import Any


class YamlUnsupported(Exception):
    pass


def safe_load(text: str) -> Any:
    lines = [l.rstrip("\n") for l in text.splitlines()]
    lines = [(len(l) - len(l.lstrip(" ")), l.strip()) for l in lines]
    lines = [(i, t) for i, t in lines if t and not t.startswith("#")]
    value, _ = _parse_block(lines, 0, 0)
    return value


def _parse_scalar(token: str) -> Any:
    t = token.strip()
    if t.startswith("[") and t.endswith("]"):
        inner = t[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(x) for x in _split_flow(inner)]
    if t.startswith('"') and t.endswith('"'):
        return t[1:-1]
    if t.startswith("'") and t.endswith("'"):
        return t[1:-1]
    if t.lower() in ("true", "yes"):
        return True
    if t.lower() in ("false", "no"):
        return False
    if t.lower() in ("null", "~"):
        return None
    try:
        return int(t) if t.lstrip("-").isdigit() else float(t)
    except ValueError:
        return t


def _split_flow(s: str) -> list[str]:
    out, cur, depth, quote = [], "", 0, None
    for ch in s:
        if quote:
            cur += ch
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            cur += ch
        elif ch == "[":
            depth += 1
            cur += ch
        elif ch == "]":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _parse_block(lines, idx: int, indent: int) -> tuple[Any, int]:
    if idx >= len(lines):
        return {}, idx

    cur_indent, first = lines[idx]
    if first.startswith("- "):
        return _parse_list(lines, idx, cur_indent)

    result: dict[str, Any] = {}
    while idx < len(lines):
        cur_indent, text = lines[idx]
        if cur_indent < indent:
            break
        if cur_indent > indent:
            raise YamlUnsupported(f"unexpected indent at: {text!r}")
        if text.startswith("- "):
            break
        if ":" not in text:
            raise YamlUnsupported(f"expected 'key: value', got {text!r}")

        key, _, rest = text.partition(":")
        key = key.strip()
        rest = rest.strip()

        if rest in ("|", ">", "|-", ">-"):
            idx += 1
            block, idx = _parse_block_scalar(lines, idx, cur_indent, folded=(rest[0] == ">"))
            result[key] = block
            continue

        if rest == "":
            idx += 1
            if idx < len(lines) and lines[idx][0] > cur_indent:
                value, idx = _parse_block(lines, idx, lines[idx][0])
            elif idx < len(lines) and lines[idx][0] == cur_indent and lines[idx][1].startswith("- "):
                value, idx = _parse_list(lines, idx, cur_indent)
            else:
                value = {}
            result[key] = value
            continue

        result[key] = _parse_scalar(rest)
        idx += 1

    return result, idx


def _parse_block_scalar(lines, idx: int, parent_indent: int, folded: bool) -> tuple[str, int]:
    collected = []
    block_indent = None
    while idx < len(lines):
        cur_indent, text = lines[idx]
        if cur_indent <= parent_indent:
            break
        if block_indent is None:
            block_indent = cur_indent
        collected.append(" " * (cur_indent - block_indent) + text)
        idx += 1
    joiner = " " if folded else "\n"
    return joiner.join(collected) + ("\n" if not folded else ""), idx


def _parse_list(lines, idx: int, indent: int) -> tuple[list[Any], int]:
    out: list[Any] = []
    while idx < len(lines):
        cur_indent, text = lines[idx]
        if cur_indent != indent or not text.startswith("- "):
            break
        item_text = text[2:].strip()
        idx += 1

        if ":" in item_text and not item_text.startswith(("[", '"', "'")):
            # A mapping item: the first key is on the dash line.
            key, _, rest = item_text.partition(":")
            item: dict[str, Any] = {}
            if rest.strip() in ("|", ">", "|-", ">-"):
                block, idx = _parse_block_scalar(lines, idx, cur_indent, folded=rest.strip()[0] == ">")
                item[key.strip()] = block
            elif rest.strip():
                item[key.strip()] = _parse_scalar(rest)
            else:
                if idx < len(lines) and lines[idx][0] > cur_indent:
                    value, idx = _parse_block(lines, idx, lines[idx][0])
                    item[key.strip()] = value
                else:
                    item[key.strip()] = {}
            # Remaining keys of this item are indented under the dash.
            while idx < len(lines) and lines[idx][0] > cur_indent and not lines[idx][1].startswith("- "):
                sub_indent = lines[idx][0]
                more, idx = _parse_block(lines, idx, sub_indent)
                if isinstance(more, dict):
                    item.update(more)
                else:
                    break
            out.append(item)
        else:
            out.append(_parse_scalar(item_text))
    return out, idx
