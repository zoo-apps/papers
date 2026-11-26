// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package verifier

import (
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// ExprErrorKind categorizes deterministic expression evaluation failures.
type ExprErrorKind int

const (
	ExprErrNone ExprErrorKind = iota
	ExprErrSyntax
	ExprErrUndefinedVar
	ExprErrDomain
)

// ExprError is a typed deterministic error returned by expression evaluation.
type ExprError struct {
	Kind ExprErrorKind
	Msg  string
}

func (e *ExprError) Error() string { return e.Msg }

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokNumber
	tokIdent
	tokPlus
	tokMinus
	tokStar
	tokSlash
	tokCaret
	tokLParen
	tokRParen
	tokComma
)

type token struct {
	kind tokenKind
	val  string
}

func tokenize(src string) ([]token, error) {
	var toks []token
	n := len(src)
	i := 0
	for i < n {
		ch := src[i]
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			i++
			continue
		}
		if (ch >= '0' && ch <= '9') || ch == '.' {
			start := i
			hasDot := false
			for i < n && ((src[i] >= '0' && src[i] <= '9') || (src[i] == '.' && !hasDot)) {
				if src[i] == '.' {
					hasDot = true
				}
				i++
			}
			if i < n && (src[i] == 'e' || src[i] == 'E') {
				j := i + 1
				if j < n && (src[j] == '+' || src[j] == '-') {
					j++
				}
				if j < n && src[j] >= '0' && src[j] <= '9' {
					i = j
					for i < n && src[i] >= '0' && src[i] <= '9' {
						i++
					}
				}
			}
			toks = append(toks, token{kind: tokNumber, val: src[start:i]})
			continue
		}
		if unicode.IsLetter(rune(ch)) || ch == '_' {
			start := i
			for i < n && (unicode.IsLetter(rune(src[i])) || unicode.IsDigit(rune(src[i])) || src[i] == '_') {
				i++
			}
			toks = append(toks, token{kind: tokIdent, val: src[start:i]})
			continue
		}
		switch ch {
		case '+':
			toks = append(toks, token{kind: tokPlus, val: "+"})
		case '-':
			toks = append(toks, token{kind: tokMinus, val: "-"})
		case '*':
			toks = append(toks, token{kind: tokStar, val: "*"})
		case '/':
			toks = append(toks, token{kind: tokSlash, val: "/"})
		case '^':
			toks = append(toks, token{kind: tokCaret, val: "^"})
		case '(':
			toks = append(toks, token{kind: tokLParen, val: "("})
		case ')':
			toks = append(toks, token{kind: tokRParen, val: ")"})
		case ',':
			toks = append(toks, token{kind: tokComma, val: ","})
		default:
			return nil, &ExprError{Kind: ExprErrSyntax, Msg: fmt.Sprintf("unexpected character %q", ch)}
		}
		i++
	}
	toks = append(toks, token{kind: tokEOF})
	return toks, nil
}

type exprNode interface{}

type numNode struct{ raw string }
type varNode struct{ name string }
type unaryNode struct {
	op    tokenKind
	child exprNode
}
type binNode struct {
	op    tokenKind
	left  exprNode
	right exprNode
}
type callNode struct {
	name string
	args []exprNode
}

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token {
	t := p.toks[p.pos]
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
	return t
}

func parseExpression(src string) (exprNode, error) {
	toks, err := tokenize(src)
	if err != nil {
		return nil, err
	}
	if len(toks) == 1 && toks[0].kind == tokEOF {
		return nil, &ExprError{Kind: ExprErrSyntax, Msg: "empty expression"}
	}
	p := &parser{toks: toks}
	node, err := p.parseAddSub()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, &ExprError{Kind: ExprErrSyntax, Msg: fmt.Sprintf("unexpected token %q", p.peek().val)}
	}
	return node, nil
}

func (p *parser) parseAddSub() (exprNode, error) {
	left, err := p.parseMulDiv()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokPlus || p.peek().kind == tokMinus {
		op := p.next().kind
		right, err := p.parseMulDiv()
		if err != nil {
			return nil, err
		}
		left = &binNode{op: op, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseMulDiv() (exprNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokStar || p.peek().kind == tokSlash {
		op := p.next().kind
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &binNode{op: op, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseUnary() (exprNode, error) {
	if p.peek().kind == tokPlus || p.peek().kind == tokMinus {
		op := p.next().kind
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &unaryNode{op: op, child: child}, nil
	}
	return p.parsePower()
}

func (p *parser) parsePower() (exprNode, error) {
	base, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	if p.peek().kind == tokCaret {
		p.next()
		exp, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &binNode{op: tokCaret, left: base, right: exp}, nil
	}
	return base, nil
}

func (p *parser) parsePrimary() (exprNode, error) {
	t := p.peek()
	switch t.kind {
	case tokNumber:
		p.next()
		return &numNode{raw: t.val}, nil
	case tokIdent:
		p.next()
		if p.peek().kind == tokLParen {
			p.next()
			var args []exprNode
			if p.peek().kind != tokRParen {
				for {
					arg, err := p.parseAddSub()
					if err != nil {
						return nil, err
					}
					args = append(args, arg)
					if p.peek().kind == tokComma {
						p.next()
						continue
					}
					break
				}
			}
			if p.peek().kind != tokRParen {
				return nil, &ExprError{Kind: ExprErrSyntax, Msg: "missing closing parenthesis"}
			}
			p.next()
			return &callNode{name: strings.ToLower(t.val), args: args}, nil
		}
		return &varNode{name: t.val}, nil
	case tokLParen:
		p.next()
		inner, err := p.parseAddSub()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, &ExprError{Kind: ExprErrSyntax, Msg: "missing closing parenthesis"}
		}
		p.next()
		return inner, nil
	default:
		return nil, &ExprError{Kind: ExprErrSyntax, Msg: fmt.Sprintf("unexpected token %q", t.val)}
	}
}

// EvalExpression evaluates a mathematical/statistical expression deterministically.
func EvalExpression(src string, vars map[string]float64, exactRational bool) (float64, error) {
	node, err := parseExpression(src)
	if err != nil {
		return 0, err
	}
	if exactRational {
		r, err := evalRational(node, vars)
		if err != nil {
			return 0, err
		}
		f, _ := r.Float64()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, &ExprError{Kind: ExprErrDomain, Msg: "non-finite rational result"}
		}
		return f, nil
	}
	v, err := evalFloat(node, vars)
	if err != nil {
		return 0, err
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, &ExprError{Kind: ExprErrDomain, Msg: "non-finite floating-point result"}
	}
	return v, nil
}

func evalFloat(node exprNode, vars map[string]float64) (float64, error) {
	switch n := node.(type) {
	case *numNode:
		f, err := strconv.ParseFloat(n.raw, 64)
		if err != nil {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: fmt.Sprintf("invalid number %q", n.raw)}
		}
		return f, nil
	case *varNode:
		if vars != nil {
			if v, ok := vars[n.name]; ok {
				return v, nil
			}
		}
		switch strings.ToLower(n.name) {
		case "pi":
			return math.Pi, nil
		case "e":
			return math.E, nil
		}
		return 0, &ExprError{Kind: ExprErrUndefinedVar, Msg: fmt.Sprintf("undefined variable %q", n.name)}
	case *unaryNode:
		v, err := evalFloat(n.child, vars)
		if err != nil {
			return 0, err
		}
		if n.op == tokMinus {
			return -v, nil
		}
		return v, nil
	case *binNode:
		l, err := evalFloat(n.left, vars)
		if err != nil {
			return 0, err
		}
		r, err := evalFloat(n.right, vars)
		if err != nil {
			return 0, err
		}
		switch n.op {
		case tokPlus:
			return l + r, nil
		case tokMinus:
			return l - r, nil
		case tokStar:
			return l * r, nil
		case tokSlash:
			if r == 0 {
				return 0, &ExprError{Kind: ExprErrDomain, Msg: "division by zero"}
			}
			return l / r, nil
		case tokCaret:
			if l < 0 && math.Trunc(r) != r {
				return 0, &ExprError{Kind: ExprErrDomain, Msg: "negative base with fractional exponent"}
			}
			if l == 0 && r < 0 {
				return 0, &ExprError{Kind: ExprErrDomain, Msg: "zero raised to negative power"}
			}
			res := math.Pow(l, r)
			if math.IsNaN(res) || math.IsInf(res, 0) {
				return 0, &ExprError{Kind: ExprErrDomain, Msg: "non-finite power"}
			}
			return res, nil
		}
	case *callNode:
		vals := make([]float64, len(n.args))
		for i, a := range n.args {
			v, err := evalFloat(a, vars)
			if err != nil {
				return 0, err
			}
			vals[i] = v
		}
		return evalBuiltinFunc(n.name, vals)
	}
	return 0, &ExprError{Kind: ExprErrSyntax, Msg: "unknown AST node"}
}

func evalBuiltinFunc(name string, vals []float64) (float64, error) {
	switch name {
	case "abs":
		if len(vals) != 1 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "abs requires 1 argument"}
		}
		return math.Abs(vals[0]), nil
	case "sqrt":
		if len(vals) != 1 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "sqrt requires 1 argument"}
		}
		if vals[0] < 0 {
			return 0, &ExprError{Kind: ExprErrDomain, Msg: "sqrt of negative number"}
		}
		return math.Sqrt(vals[0]), nil
	case "ln":
		if len(vals) != 1 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "ln requires 1 argument"}
		}
		if vals[0] <= 0 {
			return 0, &ExprError{Kind: ExprErrDomain, Msg: "ln of non-positive number"}
		}
		return math.Log(vals[0]), nil
	case "log10":
		if len(vals) != 1 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "log10 requires 1 argument"}
		}
		if vals[0] <= 0 {
			return 0, &ExprError{Kind: ExprErrDomain, Msg: "log10 of non-positive number"}
		}
		return math.Log10(vals[0]), nil
	case "exp":
		if len(vals) != 1 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "exp requires 1 argument"}
		}
		res := math.Exp(vals[0])
		if math.IsInf(res, 0) || math.IsNaN(res) {
			return 0, &ExprError{Kind: ExprErrDomain, Msg: "exp overflow"}
		}
		return res, nil
	case "floor":
		if len(vals) != 1 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "floor requires 1 argument"}
		}
		return math.Floor(vals[0]), nil
	case "ceil":
		if len(vals) != 1 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "ceil requires 1 argument"}
		}
		return math.Ceil(vals[0]), nil
	case "round":
		if len(vals) < 1 || len(vals) > 2 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "round requires 1 or 2 arguments"}
		}
		digits := 0
		if len(vals) == 2 {
			digits = int(math.Trunc(vals[1]))
		}
		pow := math.Pow10(digits)
		if vals[0] >= 0 {
			return math.Floor(vals[0]*pow+0.5) / pow, nil
		}
		return math.Ceil(vals[0]*pow-0.5) / pow, nil
	case "min":
		if len(vals) == 0 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "min requires >=1 argument"}
		}
		m := vals[0]
		for _, v := range vals[1:] {
			if v < m {
				m = v
			}
		}
		return m, nil
	case "max":
		if len(vals) == 0 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "max requires >=1 argument"}
		}
		m := vals[0]
		for _, v := range vals[1:] {
			if v > m {
				m = v
			}
		}
		return m, nil
	case "sum":
		if len(vals) == 0 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "sum requires >=1 argument"}
		}
		s := 0.0
		for _, v := range vals {
			s += v
		}
		return s, nil
	case "mean":
		if len(vals) == 0 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "mean requires >=1 argument"}
		}
		s := 0.0
		for _, v := range vals {
			s += v
		}
		return s / float64(len(vals)), nil
	case "median":
		if len(vals) == 0 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "median requires >=1 argument"}
		}
		cp := make([]float64, len(vals))
		copy(cp, vals)
		sort.Float64s(cp)
		mid := len(cp) / 2
		if len(cp)%2 == 1 {
			return cp[mid], nil
		}
		return (cp[mid-1] + cp[mid]) / 2.0, nil
	case "var":
		if len(vals) < 2 {
			return 0, &ExprError{Kind: ExprErrDomain, Msg: "var requires >=2 arguments"}
		}
		m := 0.0
		for _, v := range vals {
			m += v
		}
		m /= float64(len(vals))
		ss := 0.0
		for _, v := range vals {
			d := v - m
			ss += d * d
		}
		return ss / float64(len(vals)-1), nil
	case "std":
		if len(vals) < 2 {
			return 0, &ExprError{Kind: ExprErrDomain, Msg: "std requires >=2 arguments"}
		}
		v, err := evalBuiltinFunc("var", vals)
		if err != nil {
			return 0, err
		}
		return math.Sqrt(v), nil
	case "pct_delta":
		if len(vals) != 2 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "pct_delta requires 2 arguments"}
		}
		if vals[1] == 0 {
			return 0, &ExprError{Kind: ExprErrDomain, Msg: "pct_delta division by zero"}
		}
		return ((vals[0] - vals[1]) / vals[1]) * 100.0, nil
	case "ratio":
		if len(vals) != 2 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "ratio requires 2 arguments"}
		}
		if vals[1] == 0 {
			return 0, &ExprError{Kind: ExprErrDomain, Msg: "ratio division by zero"}
		}
		return vals[0] / vals[1], nil
	case "hoeffding_upper":
		if len(vals) != 3 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "hoeffding_upper requires 3 arguments (n, theta, p)"}
		}
		nVal, theta, pVal := vals[0], vals[1], vals[2]
		if nVal <= 0 || theta <= pVal {
			return 0, &ExprError{Kind: ExprErrDomain, Msg: "hoeffding_upper requires n > 0 and theta > p"}
		}
		diff := theta - pVal
		return math.Exp(-2.0 * nVal * diff * diff), nil
	case "ci95_halfwidth":
		if len(vals) != 2 {
			return 0, &ExprError{Kind: ExprErrSyntax, Msg: "ci95_halfwidth requires 2 arguments (std, n)"}
		}
		if vals[0] < 0 || vals[1] <= 0 {
			return 0, &ExprError{Kind: ExprErrDomain, Msg: "ci95_halfwidth requires std >= 0 and n > 0"}
		}
		return 1.96 * vals[0] / math.Sqrt(vals[1]), nil
	default:
		return 0, &ExprError{Kind: ExprErrSyntax, Msg: fmt.Sprintf("unknown function %q", name)}
	}
}

func evalRational(node exprNode, vars map[string]float64) (*big.Rat, error) {
	switch n := node.(type) {
	case *numNode:
		r, ok := new(big.Rat).SetString(n.raw)
		if !ok {
			f, err := strconv.ParseFloat(n.raw, 64)
			if err != nil {
				return nil, &ExprError{Kind: ExprErrSyntax, Msg: fmt.Sprintf("invalid number %q", n.raw)}
			}
			r = new(big.Rat).SetFloat64(f)
			if r == nil {
				return nil, &ExprError{Kind: ExprErrDomain, Msg: "non-finite number"}
			}
		}
		return r, nil
	case *varNode:
		if vars != nil {
			if v, ok := vars[n.name]; ok {
				s := strconv.FormatFloat(v, 'g', 17, 64)
				if r, ok := new(big.Rat).SetString(s); ok {
					return r, nil
				}
				r := new(big.Rat).SetFloat64(v)
				if r == nil {
					return nil, &ExprError{Kind: ExprErrDomain, Msg: "non-finite variable"}
				}
				return r, nil
			}
		}
		return nil, &ExprError{Kind: ExprErrUndefinedVar, Msg: fmt.Sprintf("undefined variable %q", n.name)}
	case *unaryNode:
		v, err := evalRational(n.child, vars)
		if err != nil {
			return nil, err
		}
		if n.op == tokMinus {
			return new(big.Rat).Neg(v), nil
		}
		return v, nil
	case *binNode:
		l, err := evalRational(n.left, vars)
		if err != nil {
			return nil, err
		}
		r, err := evalRational(n.right, vars)
		if err != nil {
			return nil, err
		}
		switch n.op {
		case tokPlus:
			return new(big.Rat).Add(l, r), nil
		case tokMinus:
			return new(big.Rat).Sub(l, r), nil
		case tokStar:
			return new(big.Rat).Mul(l, r), nil
		case tokSlash:
			if r.Sign() == 0 {
				return nil, &ExprError{Kind: ExprErrDomain, Msg: "division by zero"}
			}
			return new(big.Rat).Quo(l, r), nil
		case tokCaret:
			if !r.IsInt() {
				return nil, &ExprError{Kind: ExprErrDomain, Msg: "exact rational mode requires integer exponent"}
			}
			exp := r.Num().Int64()
			if exp > 1000 || exp < -1000 {
				return nil, &ExprError{Kind: ExprErrDomain, Msg: "exponent out of bounds"}
			}
			if exp == 0 {
				return big.NewRat(1, 1), nil
			}
			base := new(big.Rat).Set(l)
			if exp < 0 {
				if base.Sign() == 0 {
					return nil, &ExprError{Kind: ExprErrDomain, Msg: "zero raised to negative power"}
				}
				base = new(big.Rat).Inv(base)
				exp = -exp
			}
			res := big.NewRat(1, 1)
			for i := int64(0); i < exp; i++ {
				res.Mul(res, base)
			}
			return res, nil
		}
	case *callNode:
		// Support exact rational ratio/pct_delta/sum/mean/abs.
		vals := make([]*big.Rat, len(n.args))
		for i, a := range n.args {
			v, err := evalRational(a, vars)
			if err != nil {
				return nil, err
			}
			vals[i] = v
		}
		switch n.name {
		case "abs":
			if len(vals) != 1 {
				return nil, &ExprError{Kind: ExprErrSyntax, Msg: "abs requires 1 argument"}
			}
			return new(big.Rat).Abs(vals[0]), nil
		case "sum":
			if len(vals) == 0 {
				return nil, &ExprError{Kind: ExprErrSyntax, Msg: "sum requires >=1 argument"}
			}
			s := big.NewRat(0, 1)
			for _, v := range vals {
				s.Add(s, v)
			}
			return s, nil
		case "mean":
			if len(vals) == 0 {
				return nil, &ExprError{Kind: ExprErrSyntax, Msg: "mean requires >=1 argument"}
			}
			s := big.NewRat(0, 1)
			for _, v := range vals {
				s.Add(s, v)
			}
			return s.Quo(s, big.NewRat(int64(len(vals)), 1)), nil
		case "ratio":
			if len(vals) != 2 {
				return nil, &ExprError{Kind: ExprErrSyntax, Msg: "ratio requires 2 arguments"}
			}
			if vals[1].Sign() == 0 {
				return nil, &ExprError{Kind: ExprErrDomain, Msg: "ratio division by zero"}
			}
			return new(big.Rat).Quo(vals[0], vals[1]), nil
		case "pct_delta":
			if len(vals) != 2 {
				return nil, &ExprError{Kind: ExprErrSyntax, Msg: "pct_delta requires 2 arguments"}
			}
			if vals[1].Sign() == 0 {
				return nil, &ExprError{Kind: ExprErrDomain, Msg: "pct_delta division by zero"}
			}
			diff := new(big.Rat).Sub(vals[0], vals[1])
			q := new(big.Rat).Quo(diff, vals[1])
			return q.Mul(q, big.NewRat(100, 1)), nil
		default:
			return nil, &ExprError{Kind: ExprErrSyntax, Msg: fmt.Sprintf("function %q not supported in exact rational mode", n.name)}
		}
	}
	return nil, &ExprError{Kind: ExprErrSyntax, Msg: "unknown AST node"}
}
