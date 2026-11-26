# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation

"""Deterministic LL(1) math and statistics AST evaluator with exact rational mode."""

from __future__ import annotations

import math
from dataclasses import dataclass
from fractions import Fraction
from typing import Any

EXPR_ERR_SYNTAX = "syntax"
EXPR_ERR_UNDEFINED_VAR = "undefined_var"
EXPR_ERR_DOMAIN = "domain"


class ExprError(Exception):
    def __init__(self, kind: str, msg: str) -> None:
        super().__init__(msg)
        self.kind = kind
        self.msg = msg


@dataclass(frozen=True)
class Token:
    kind: str
    val: str


def tokenize(src: str) -> list[Token]:
    toks: list[Token] = []
    n = len(src)
    i = 0
    while i < n:
        ch = src[i]
        if ch in " \t\n\r":
            i += 1
            continue
        if ("0" <= ch <= "9") or ch == ".":
            start = i
            has_dot = False
            while i < n and (("0" <= src[i] <= "9") or (src[i] == "." and not has_dot)):
                if src[i] == ".":
                    has_dot = True
                i += 1
            if i < n and src[i] in ("e", "E"):
                j = i + 1
                if j < n and src[j] in ("+", "-"):
                    j += 1
                if j < n and "0" <= src[j] <= "9":
                    i = j
                    while i < n and "0" <= src[i] <= "9":
                        i += 1
            toks.append(Token("NUMBER", src[start:i]))
            continue
        if ch.isalpha() or ch == "_":
            start = i
            while i < n and (src[i].isalnum() or src[i] == "_"):
                i += 1
            toks.append(Token("IDENT", src[start:i]))
            continue
        single = {
            "+": "PLUS",
            "-": "MINUS",
            "*": "STAR",
            "/": "SLASH",
            "^": "CARET",
            "(": "LPAREN",
            ")": "RPAREN",
            ",": "COMMA",
        }
        if ch in single:
            toks.append(Token(single[ch], ch))
            i += 1
            continue
        raise ExprError(EXPR_ERR_SYNTAX, f'unexpected character "{ch}"')
    toks.append(Token("EOF", ""))
    return toks


class _Parser:
    def __init__(self, toks: list[Token]) -> None:
        self.toks = toks
        self.pos = 0

    def peek(self) -> Token:
        return self.toks[self.pos]

    def nxt(self) -> Token:
        t = self.toks[self.pos]
        if self.pos < len(self.toks) - 1:
            self.pos += 1
        return t

    def parse_add_sub(self) -> Any:
        left = self.parse_mul_div()
        while self.peek().kind in ("PLUS", "MINUS"):
            op = self.nxt().kind
            right = self.parse_mul_div()
            left = ("BIN", op, left, right)
        return left

    def parse_mul_div(self) -> Any:
        left = self.parse_unary()
        while self.peek().kind in ("STAR", "SLASH"):
            op = self.nxt().kind
            right = self.parse_unary()
            left = ("BIN", op, left, right)
        return left

    def parse_unary(self) -> Any:
        if self.peek().kind in ("PLUS", "MINUS"):
            op = self.nxt().kind
            return ("UNARY", op, self.parse_unary())
        return self.parse_power()

    def parse_power(self) -> Any:
        base = self.parse_primary()
        if self.peek().kind == "CARET":
            self.nxt()
            exp = self.parse_unary()
            return ("BIN", "CARET", base, exp)
        return base

    def parse_primary(self) -> Any:
        t = self.peek()
        if t.kind == "NUMBER":
            self.nxt()
            return ("NUM", t.val)
        if t.kind == "IDENT":
            self.nxt()
            if self.peek().kind == "LPAREN":
                self.nxt()
                args: list[Any] = []
                if self.peek().kind != "RPAREN":
                    while True:
                        args.append(self.parse_add_sub())
                        if self.peek().kind == "COMMA":
                            self.nxt()
                            continue
                        break
                if self.peek().kind != "RPAREN":
                    raise ExprError(EXPR_ERR_SYNTAX, "missing closing parenthesis")
                self.nxt()
                return ("CALL", t.val.lower(), args)
            return ("VAR", t.val)
        if t.kind == "LPAREN":
            self.nxt()
            inner = self.parse_add_sub()
            if self.peek().kind != "RPAREN":
                raise ExprError(EXPR_ERR_SYNTAX, "missing closing parenthesis")
            self.nxt()
            return inner
        raise ExprError(EXPR_ERR_SYNTAX, f'unexpected token "{t.val}"')


def parse_expression(src: str) -> Any:
    toks = tokenize(src)
    if len(toks) == 1 and toks[0].kind == "EOF":
        raise ExprError(EXPR_ERR_SYNTAX, "empty expression")
    p = _Parser(toks)
    node = p.parse_add_sub()
    if p.peek().kind != "EOF":
        raise ExprError(EXPR_ERR_SYNTAX, f'unexpected token "{p.peek().val}"')
    return node


def eval_expression(
    src: str, variables: dict[str, float] | None = None, exact_rational: bool = False
) -> float:
    node = parse_expression(src)
    vars_map = variables or {}
    if exact_rational:
        rat = _eval_rational(node, vars_map)
        val = float(rat)
        if math.isnan(val) or math.isinf(val):
            raise ExprError(EXPR_ERR_DOMAIN, "non-finite rational result")
        return val
    val = _eval_float(node, vars_map)
    if math.isnan(val) or math.isinf(val):
        raise ExprError(EXPR_ERR_DOMAIN, "non-finite floating-point result")
    return val


def _eval_float(node: Any, vars_map: dict[str, float]) -> float:
    kind = node[0]
    if kind == "NUM":
        try:
            return float(node[1])
        except ValueError as exc:
            raise ExprError(EXPR_ERR_SYNTAX, f'invalid number "{node[1]}"') from exc
    if kind == "VAR":
        name = node[1]
        if name in vars_map:
            return float(vars_map[name])
        low = name.lower()
        if low == "pi":
            return math.pi
        if low == "e":
            return math.e
        raise ExprError(EXPR_ERR_UNDEFINED_VAR, f'undefined variable "{name}"')
    if kind == "UNARY":
        v = _eval_float(node[2], vars_map)
        return -v if node[1] == "MINUS" else v
    if kind == "BIN":
        op = node[1]
        l = _eval_float(node[2], vars_map)
        r = _eval_float(node[3], vars_map)
        if op == "PLUS":
            return l + r
        if op == "MINUS":
            return l - r
        if op == "STAR":
            return l * r
        if op == "SLASH":
            if r == 0:
                raise ExprError(EXPR_ERR_DOMAIN, "division by zero")
            return l / r
        if op == "CARET":
            if l < 0 and math.trunc(r) != r:
                raise ExprError(EXPR_ERR_DOMAIN, "negative base with fractional exponent")
            if l == 0 and r < 0:
                raise ExprError(EXPR_ERR_DOMAIN, "zero raised to negative power")
            try:
                res = math.pow(l, r)
            except (ValueError, OverflowError) as exc:
                raise ExprError(EXPR_ERR_DOMAIN, "non-finite power") from exc
            if math.isnan(res) or math.isinf(res):
                raise ExprError(EXPR_ERR_DOMAIN, "non-finite power")
            return res
    if kind == "CALL":
        vals = [_eval_float(a, vars_map) for a in node[2]]
        return _eval_builtin_func(node[1], vals)
    raise ExprError(EXPR_ERR_SYNTAX, "unknown AST node")


def _eval_builtin_func(name: str, vals: list[float]) -> float:
    if name == "abs":
        if len(vals) != 1:
            raise ExprError(EXPR_ERR_SYNTAX, "abs requires 1 argument")
        return abs(vals[0])
    if name == "sqrt":
        if len(vals) != 1:
            raise ExprError(EXPR_ERR_SYNTAX, "sqrt requires 1 argument")
        if vals[0] < 0:
            raise ExprError(EXPR_ERR_DOMAIN, "sqrt of negative number")
        return math.sqrt(vals[0])
    if name == "ln":
        if len(vals) != 1:
            raise ExprError(EXPR_ERR_SYNTAX, "ln requires 1 argument")
        if vals[0] <= 0:
            raise ExprError(EXPR_ERR_DOMAIN, "ln of non-positive number")
        return math.log(vals[0])
    if name == "log10":
        if len(vals) != 1:
            raise ExprError(EXPR_ERR_SYNTAX, "log10 requires 1 argument")
        if vals[0] <= 0:
            raise ExprError(EXPR_ERR_DOMAIN, "log10 of non-positive number")
        return math.log10(vals[0])
    if name == "exp":
        if len(vals) != 1:
            raise ExprError(EXPR_ERR_SYNTAX, "exp requires 1 argument")
        try:
            res = math.exp(vals[0])
        except OverflowError as exc:
            raise ExprError(EXPR_ERR_DOMAIN, "exp overflow") from exc
        if math.isinf(res) or math.isnan(res):
            raise ExprError(EXPR_ERR_DOMAIN, "exp overflow")
        return res
    if name == "floor":
        if len(vals) != 1:
            raise ExprError(EXPR_ERR_SYNTAX, "floor requires 1 argument")
        return float(math.floor(vals[0]))
    if name == "ceil":
        if len(vals) != 1:
            raise ExprError(EXPR_ERR_SYNTAX, "ceil requires 1 argument")
        return float(math.ceil(vals[0]))
    if name == "round":
        if len(vals) < 1 or len(vals) > 2:
            raise ExprError(EXPR_ERR_SYNTAX, "round requires 1 or 2 arguments")
        digits = int(math.trunc(vals[1])) if len(vals) == 2 else 0
        p10 = 10.0 ** digits
        if vals[0] >= 0:
            return math.floor(vals[0] * p10 + 0.5) / p10
        return math.ceil(vals[0] * p10 - 0.5) / p10
    if name == "min":
        if not vals:
            raise ExprError(EXPR_ERR_SYNTAX, "min requires >=1 argument")
        return min(vals)
    if name == "max":
        if not vals:
            raise ExprError(EXPR_ERR_SYNTAX, "max requires >=1 argument")
        return max(vals)
    if name == "sum":
        if not vals:
            raise ExprError(EXPR_ERR_SYNTAX, "sum requires >=1 argument")
        return sum(vals)
    if name == "mean":
        if not vals:
            raise ExprError(EXPR_ERR_SYNTAX, "mean requires >=1 argument")
        return sum(vals) / len(vals)
    if name == "median":
        if not vals:
            raise ExprError(EXPR_ERR_SYNTAX, "median requires >=1 argument")
        s = sorted(vals)
        mid = len(s) // 2
        if len(s) % 2 == 1:
            return s[mid]
        return (s[mid - 1] + s[mid]) / 2.0
    if name == "var":
        if len(vals) < 2:
            raise ExprError(EXPR_ERR_DOMAIN, "var requires >=2 arguments")
        m = sum(vals) / len(vals)
        return sum((x - m) ** 2 for x in vals) / (len(vals) - 1)
    if name == "std":
        if len(vals) < 2:
            raise ExprError(EXPR_ERR_DOMAIN, "std requires >=2 arguments")
        return math.sqrt(_eval_builtin_func("var", vals))
    if name == "pct_delta":
        if len(vals) != 2:
            raise ExprError(EXPR_ERR_SYNTAX, "pct_delta requires 2 arguments")
        if vals[1] == 0:
            raise ExprError(EXPR_ERR_DOMAIN, "pct_delta division by zero")
        return ((vals[0] - vals[1]) / vals[1]) * 100.0
    if name == "ratio":
        if len(vals) != 2:
            raise ExprError(EXPR_ERR_SYNTAX, "ratio requires 2 arguments")
        if vals[1] == 0:
            raise ExprError(EXPR_ERR_DOMAIN, "ratio division by zero")
        return vals[0] / vals[1]
    if name == "hoeffding_upper":
        if len(vals) != 3:
            raise ExprError(EXPR_ERR_SYNTAX, "hoeffding_upper requires 3 arguments (n, theta, p)")
        n_val, theta, p_val = vals
        if n_val <= 0 or theta <= p_val:
            raise ExprError(EXPR_ERR_DOMAIN, "hoeffding_upper requires n > 0 and theta > p")
        diff = theta - p_val
        return math.exp(-2.0 * n_val * diff * diff)
    if name == "ci95_halfwidth":
        if len(vals) != 2:
            raise ExprError(EXPR_ERR_SYNTAX, "ci95_halfwidth requires 2 arguments (std, n)")
        if vals[0] < 0 or vals[1] <= 0:
            raise ExprError(EXPR_ERR_DOMAIN, "ci95_halfwidth requires std >= 0 and n > 0")
        return 1.96 * vals[0] / math.sqrt(vals[1])
    raise ExprError(EXPR_ERR_SYNTAX, f'unknown function "{name}"')


def _eval_rational(node: Any, vars_map: dict[str, float]) -> Fraction:
    kind = node[0]
    if kind == "NUM":
        try:
            return Fraction(node[1])
        except ValueError as exc:
            raise ExprError(EXPR_ERR_SYNTAX, f'invalid number "{node[1]}"') from exc
    if kind == "VAR":
        name = node[1]
        if name in vars_map:
            return Fraction(str(vars_map[name]))
        raise ExprError(EXPR_ERR_UNDEFINED_VAR, f'undefined variable "{name}"')
    if kind == "UNARY":
        v = _eval_rational(node[2], vars_map)
        return -v if node[1] == "MINUS" else v
    if kind == "BIN":
        op = node[1]
        l = _eval_rational(node[2], vars_map)
        r = _eval_rational(node[3], vars_map)
        if op == "PLUS":
            return l + r
        if op == "MINUS":
            return l - r
        if op == "STAR":
            return l * r
        if op == "SLASH":
            if r == 0:
                raise ExprError(EXPR_ERR_DOMAIN, "division by zero")
            return l / r
        if op == "CARET":
            if r.denominator != 1:
                raise ExprError(EXPR_ERR_DOMAIN, "exact rational mode requires integer exponent")
            exp = r.numerator
            if exp > 1000 or exp < -1000:
                raise ExprError(EXPR_ERR_DOMAIN, "exponent out of bounds")
            if exp < 0 and l == 0:
                raise ExprError(EXPR_ERR_DOMAIN, "zero raised to negative power")
            return l ** exp
    if kind == "CALL":
        name = node[1]
        vals = [_eval_rational(a, vars_map) for a in node[2]]
        if name == "abs":
            if len(vals) != 1:
                raise ExprError(EXPR_ERR_SYNTAX, "abs requires 1 argument")
            return abs(vals[0])
        if name == "sum":
            if not vals:
                raise ExprError(EXPR_ERR_SYNTAX, "sum requires >=1 argument")
            return sum(vals, Fraction(0))
        if name == "mean":
            if not vals:
                raise ExprError(EXPR_ERR_SYNTAX, "mean requires >=1 argument")
            return sum(vals, Fraction(0)) / len(vals)
        if name == "ratio":
            if len(vals) != 2:
                raise ExprError(EXPR_ERR_SYNTAX, "ratio requires 2 arguments")
            if vals[1] == 0:
                raise ExprError(EXPR_ERR_DOMAIN, "ratio division by zero")
            return vals[0] / vals[1]
        if name == "pct_delta":
            if len(vals) != 2:
                raise ExprError(EXPR_ERR_SYNTAX, "pct_delta requires 2 arguments")
            if vals[1] == 0:
                raise ExprError(EXPR_ERR_DOMAIN, "pct_delta division by zero")
            return ((vals[0] - vals[1]) / vals[1]) * Fraction(100)
        raise ExprError(EXPR_ERR_SYNTAX, f'function "{name}" not supported in exact rational mode')
    raise ExprError(EXPR_ERR_SYNTAX, "unknown AST node")
