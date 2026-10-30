"""Safe DSL parser/evaluator for threat-hunting queries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class QueryDslError(ValueError):
    code: str
    message: str
    position: int | None = None

    def __str__(self) -> str:
        if self.position is None:
            return f"{self.code}: {self.message}"
        return f"{self.code} at {self.position}: {self.message}"

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.position is not None:
            payload["position"] = int(self.position)
        return payload


@dataclass(frozen=True)
class _Token:
    kind: str
    text: str
    position: int


def _dsl_error(code: str, message: str, position: int | None = None) -> QueryDslError:
    return QueryDslError(code=code, message=message, position=position)


def _is_word_char(ch: str) -> bool:
    return ch.isalnum() or ch in "._-"


def _read_string(source: str, quote: str, start: int) -> tuple[str, int]:
    chars: list[str] = []
    index = start + 1
    escaped = False
    while index < len(source):
        ch = source[index]
        if escaped:
            if ch == "n":
                chars.append("\n")
            elif ch == "t":
                chars.append("\t")
            else:
                chars.append(ch)
            escaped = False
            index += 1
            continue
        if ch == "\\":
            escaped = True
            index += 1
            continue
        if ch == quote:
            return ("".join(chars), index + 1)
        chars.append(ch)
        index += 1
    raise _dsl_error("unterminated_string", "Unterminated string literal", start)


def _read_number(source: str, start: int) -> tuple[str, int]:
    index = start
    if source[index] == "-":
        index += 1
    has_digits = False
    has_dot = False
    while index < len(source):
        ch = source[index]
        if ch.isdigit():
            has_digits = True
            index += 1
            continue
        if ch == "." and not has_dot:
            has_dot = True
            index += 1
            continue
        break
    if not has_digits:
        raise _dsl_error("invalid_number", "Invalid numeric literal", start)
    return (source[start:index], index)


def _to_number(text: str, position: int) -> float | int:
    try:
        if "." in text:
            return float(text)
        return int(text)
    except ValueError as exc:
        raise _dsl_error("invalid_number", "Invalid numeric literal", position) from exc


def _tokenize(
    query: str,
    *,
    max_tokens: int,
) -> list[_Token]:
    tokens: list[_Token] = []
    idx = 0
    while idx < len(query):
        ch = query[idx]
        if ch.isspace():
            idx += 1
            continue
        if ch in "()[],":
            kind = {
                "(": "LPAREN",
                ")": "RPAREN",
                "[": "LBRACK",
                "]": "RBRACK",
                ",": "COMMA",
            }[ch]
            tokens.append(_Token(kind=kind, text=ch, position=idx))
            idx += 1
            continue
        if ch in ("'", '"'):
            text, idx = _read_string(query, ch, idx)
            tokens.append(_Token(kind="STRING", text=text, position=idx - len(text) - 2))
            continue
        if ch.isdigit() or (ch == "-" and idx + 1 < len(query) and query[idx + 1].isdigit()):
            text, idx = _read_number(query, idx)
            tokens.append(_Token(kind="NUMBER", text=text, position=idx - len(text)))
            continue
        if ch in ("=", "!", ">", "<"):
            if idx + 1 < len(query) and query[idx + 1] == "=":
                op = query[idx : idx + 2]
                idx += 2
            elif ch in (">", "<"):
                op = ch
                idx += 1
            else:
                raise _dsl_error("invalid_operator", "Unsupported operator", idx)
            tokens.append(_Token(kind="OP", text=op, position=idx - len(op)))
            continue
        if ch.isalpha() or ch == "_":
            start = idx
            idx += 1
            while idx < len(query) and _is_word_char(query[idx]):
                idx += 1
            text = query[start:idx]
            lower = text.lower()
            if lower in {
                "and",
                "or",
                "not",
                "in",
                "contains",
                "startswith",
                "endswith",
                "is",
                "empty",
                "non-empty",
                "null",
                "true",
                "false",
            }:
                tokens.append(_Token(kind="KEYWORD", text=lower, position=start))
            else:
                tokens.append(_Token(kind="IDENT", text=text, position=start))
            continue
        raise _dsl_error("invalid_token", f"Unexpected character '{ch}'", idx)
    if len(tokens) > max_tokens:
        raise _dsl_error("too_many_tokens", "Query exceeds token limit")
    tokens.append(_Token(kind="EOF", text="", position=len(query)))
    return tokens


def _safe_lower(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _resolve_field(record: dict[str, Any], field_path: str) -> Any:
    if field_path in record:
        return record.get(field_path)
    cursor: Any = record
    for segment in field_path.split("."):
        if not isinstance(cursor, dict):
            return None
        if segment not in cursor:
            return None
        cursor = cursor.get(segment)
    return cursor


class _Parser:
    def __init__(
        self,
        *,
        tokens: list[_Token],
        allowed_fields: set[str],
        max_depth: int,
        max_list_items: int,
    ) -> None:
        self._tokens = tokens
        self._index = 0
        self._allowed_fields = allowed_fields
        self._max_depth = max_depth
        self._max_list_items = max_list_items

    def parse(self) -> dict[str, Any]:
        node = self._parse_or(depth=0)
        if self._peek().kind != "EOF":
            token = self._peek()
            raise _dsl_error("invalid_syntax", "Unexpected trailing token", token.position)
        return node

    def _peek(self) -> _Token:
        return self._tokens[self._index]

    def _consume(self) -> _Token:
        token = self._tokens[self._index]
        self._index += 1
        return token

    def _match(self, *, kind: str, text: str | None = None) -> bool:
        token = self._peek()
        if token.kind != kind:
            return False
        if text is not None and token.text != text:
            return False
        self._consume()
        return True

    def _expect(self, *, kind: str, text: str | None = None, message: str) -> _Token:
        token = self._peek()
        if token.kind != kind or (text is not None and token.text != text):
            raise _dsl_error("invalid_syntax", message, token.position)
        return self._consume()

    def _parse_or(self, *, depth: int) -> dict[str, Any]:
        if depth > self._max_depth:
            raise _dsl_error("max_depth_exceeded", "Query nesting is too deep")
        node = self._parse_and(depth=depth + 1)
        while self._match(kind="KEYWORD", text="or"):
            right = self._parse_and(depth=depth + 1)
            node = {"kind": "logical", "op": "or", "left": node, "right": right}
        return node

    def _parse_and(self, *, depth: int) -> dict[str, Any]:
        node = self._parse_not(depth=depth + 1)
        while self._match(kind="KEYWORD", text="and"):
            right = self._parse_not(depth=depth + 1)
            node = {"kind": "logical", "op": "and", "left": node, "right": right}
        return node

    def _parse_not(self, *, depth: int) -> dict[str, Any]:
        if self._match(kind="KEYWORD", text="not"):
            operand = self._parse_not(depth=depth + 1)
            return {"kind": "unary", "op": "not", "operand": operand}
        return self._parse_predicate(depth=depth + 1)

    def _parse_predicate(self, *, depth: int) -> dict[str, Any]:
        left = self._parse_primary(field_context=True, depth=depth + 1)

        token = self._peek()
        if token.kind == "OP":
            op_token = self._consume()
            rhs = self._parse_primary(field_context=False, depth=depth + 1)
            return {
                "kind": "compare",
                "op": {
                    "==": "eq",
                    "!=": "ne",
                    ">": "gt",
                    ">=": "gte",
                    "<": "lt",
                    "<=": "lte",
                }[op_token.text],
                "left": left,
                "right": rhs,
            }
        if token.kind == "KEYWORD":
            keyword = token.text
            if keyword == "in":
                self._consume()
                return {"kind": "compare", "op": "in", "left": left, "right": self._parse_collection()}
            if keyword == "not":
                self._consume()
                self._expect(kind="KEYWORD", text="in", message="Expected 'in' after 'not'")
                return {
                    "kind": "compare",
                    "op": "not_in",
                    "left": left,
                    "right": self._parse_collection(),
                }
            if keyword in {"contains", "startswith", "endswith"}:
                self._consume()
                rhs = self._parse_primary(field_context=False, depth=depth + 1)
                return {
                    "kind": "compare",
                    "op": keyword,
                    "left": left,
                    "right": rhs,
                }
            if keyword == "is":
                self._consume()
                if self._match(kind="KEYWORD", text="not"):
                    if self._match(kind="KEYWORD", text="null"):
                        return {"kind": "compare", "op": "is_not_null", "left": left, "right": None}
                    if self._match(kind="KEYWORD", text="empty") or self._match(
                        kind="KEYWORD", text="non-empty"
                    ):
                        return {"kind": "compare", "op": "is_non_empty", "left": left, "right": None}
                    raise _dsl_error("invalid_syntax", "Expected 'null' or 'empty' after 'is not'", token.position)
                if self._match(kind="KEYWORD", text="null"):
                    return {"kind": "compare", "op": "is_null", "left": left, "right": None}
                if self._match(kind="KEYWORD", text="empty"):
                    return {"kind": "compare", "op": "is_empty", "left": left, "right": None}
                if self._match(kind="KEYWORD", text="non-empty"):
                    return {"kind": "compare", "op": "is_non_empty", "left": left, "right": None}
                raise _dsl_error("invalid_syntax", "Expected 'null' or 'empty' after 'is'", token.position)
        return left

    def _parse_collection(self) -> dict[str, Any]:
        opener = self._peek()
        if opener.kind not in {"LPAREN", "LBRACK"}:
            raise _dsl_error("invalid_syntax", "Expected list or tuple literal", opener.position)
        closer = "RPAREN" if opener.kind == "LPAREN" else "RBRACK"
        self._consume()
        items: list[Any] = []
        if self._peek().kind == closer:
            self._consume()
            return {"kind": "literal", "value": items}
        while True:
            value = self._parse_literal_value()
            items.append(value)
            if len(items) > self._max_list_items:
                raise _dsl_error("list_too_large", "List literal exceeds max item count", opener.position)
            if self._match(kind="COMMA"):
                continue
            self._expect(kind=closer, message="Expected list closing bracket")
            break
        return {"kind": "literal", "value": items}

    def _parse_primary(self, *, field_context: bool, depth: int) -> dict[str, Any]:
        if depth > self._max_depth:
            raise _dsl_error("max_depth_exceeded", "Query nesting is too deep")
        token = self._peek()
        if token.kind == "LPAREN":
            self._consume()
            expr = self._parse_or(depth=depth + 1)
            self._expect(kind="RPAREN", message="Expected closing parenthesis")
            return expr
        if token.kind == "IDENT":
            ident = self._consume().text
            if field_context:
                if ident not in self._allowed_fields:
                    raise _dsl_error("unsupported_field", f"Field '{ident}' is not allowed", token.position)
                return {"kind": "field", "name": ident}
            return {"kind": "literal", "value": ident}
        if token.kind in {"NUMBER", "STRING"} or (
            token.kind == "KEYWORD" and token.text in {"true", "false", "null"}
        ):
            return {"kind": "literal", "value": self._parse_literal_value()}
        raise _dsl_error("invalid_syntax", "Unexpected token", token.position)

    def _parse_literal_value(self) -> Any:
        token = self._peek()
        if token.kind == "NUMBER":
            return _to_number(self._consume().text, token.position)
        if token.kind == "STRING":
            return self._consume().text
        if token.kind == "IDENT":
            return self._consume().text
        if token.kind == "KEYWORD":
            keyword = self._consume().text
            if keyword == "true":
                return True
            if keyword == "false":
                return False
            if keyword == "null":
                return None
        raise _dsl_error("invalid_syntax", "Expected literal value", token.position)


@dataclass(frozen=True)
class CompiledDslQuery:
    query: str
    allowed_fields: tuple[str, ...]
    ast: dict[str, Any]
    max_depth: int

    def evaluate(self, record: dict[str, Any]) -> bool:
        return bool(_eval_node(self.ast, record, depth=0, max_depth=self.max_depth))


def _compare_eq(left: Any, right: Any) -> bool:
    left_num = _to_float(left)
    right_num = _to_float(right)
    if left_num is not None and right_num is not None:
        return left_num == right_num
    return _safe_lower(left) == _safe_lower(right)


def _compare_ordered(left: Any, right: Any, *, op: str) -> bool:
    left_num = _to_float(left)
    right_num = _to_float(right)
    if left_num is not None and right_num is not None:
        if op == "gt":
            return left_num > right_num
        if op == "gte":
            return left_num >= right_num
        if op == "lt":
            return left_num < right_num
        return left_num <= right_num
    left_text = _safe_lower(left)
    right_text = _safe_lower(right)
    if op == "gt":
        return left_text > right_text
    if op == "gte":
        return left_text >= right_text
    if op == "lt":
        return left_text < right_text
    return left_text <= right_text


def _is_empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    return False


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    return bool(value)


def _eval_node(node: dict[str, Any], record: dict[str, Any], *, depth: int, max_depth: int) -> Any:
    if depth > max_depth:
        raise _dsl_error("max_depth_exceeded", "Evaluation depth exceeded")
    kind = node.get("kind")
    if kind == "literal":
        return node.get("value")
    if kind == "field":
        return _resolve_field(record, str(node.get("name")))
    if kind == "unary":
        op = node.get("op")
        if op == "not":
            return not _truthy(_eval_node(node["operand"], record, depth=depth + 1, max_depth=max_depth))
        raise _dsl_error("unsupported_operator", f"Unsupported unary operator '{op}'")
    if kind == "logical":
        op = node.get("op")
        if op == "and":
            left = _truthy(_eval_node(node["left"], record, depth=depth + 1, max_depth=max_depth))
            if not left:
                return False
            return _truthy(_eval_node(node["right"], record, depth=depth + 1, max_depth=max_depth))
        if op == "or":
            left = _truthy(_eval_node(node["left"], record, depth=depth + 1, max_depth=max_depth))
            if left:
                return True
            return _truthy(_eval_node(node["right"], record, depth=depth + 1, max_depth=max_depth))
        raise _dsl_error("unsupported_operator", f"Unsupported logical operator '{op}'")
    if kind == "compare":
        op = str(node.get("op"))
        left = _eval_node(node["left"], record, depth=depth + 1, max_depth=max_depth)
        if op == "is_null":
            return left is None
        if op == "is_not_null":
            return left is not None
        if op == "is_empty":
            return _is_empty(left)
        if op == "is_non_empty":
            return not _is_empty(left)
        right = _eval_node(node["right"], record, depth=depth + 1, max_depth=max_depth)
        if op == "eq":
            return _compare_eq(left, right)
        if op == "ne":
            return not _compare_eq(left, right)
        if op in {"gt", "gte", "lt", "lte"}:
            return _compare_ordered(left, right, op=op)
        if op in {"in", "not_in"}:
            right_values: list[Any]
            if isinstance(right, list):
                right_values = right
            else:
                right_values = [right]
            found = any(_compare_eq(left, item) for item in right_values)
            return found if op == "in" else not found
        if op == "contains":
            if isinstance(left, str):
                return _safe_lower(right) in _safe_lower(left)
            if isinstance(left, (list, tuple, set)):
                return any(_compare_eq(item, right) for item in left)
            if isinstance(left, dict):
                return _safe_lower(right) in {_safe_lower(key) for key in left.keys()}
            return False
        if op == "startswith":
            return _safe_lower(left).startswith(_safe_lower(right))
        if op == "endswith":
            return _safe_lower(left).endswith(_safe_lower(right))
        raise _dsl_error("unsupported_operator", f"Unsupported comparison operator '{op}'")
    raise _dsl_error("invalid_syntax", "Invalid query expression")


def compile_query(
    query: str,
    *,
    allowed_fields: Iterable[str],
    max_query_length: int = 512,
    max_tokens: int = 256,
    max_depth: int = 16,
    max_list_items: int = 50,
) -> CompiledDslQuery:
    normalized_query = str(query or "").strip()
    if not normalized_query:
        raise _dsl_error("empty_query", "Query cannot be empty")
    if len(normalized_query) > max_query_length:
        raise _dsl_error("query_too_long", f"Query exceeds {max_query_length} characters")
    fields = tuple(sorted({str(field).strip() for field in allowed_fields if str(field).strip()}))
    if not fields:
        raise _dsl_error("invalid_configuration", "No allowlisted fields were configured")
    tokens = _tokenize(normalized_query, max_tokens=max_tokens)
    parser = _Parser(
        tokens=tokens,
        allowed_fields=set(fields),
        max_depth=max_depth,
        max_list_items=max_list_items,
    )
    ast = parser.parse()
    return CompiledDslQuery(
        query=normalized_query,
        allowed_fields=fields,
        ast=ast,
        max_depth=max_depth,
    )
