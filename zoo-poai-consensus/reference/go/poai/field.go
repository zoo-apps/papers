// Copyright 2026 Zoo Labs Foundation & Hanzo Industries.
// SPDX-License-Identifier: Apache-2.0

package poai

import "fmt"

// FieldModulus is the Mersenne prime p = 2^31 - 1 = 2147483647.
// For any u, v in [0, p-1] and acc in [0, p-1], acc + u*v <= p*(p-1) < 2^62 < MaxInt64,
// guaranteeing zero signed int64 overflow across all modular multiply-accumulate operations.
// For int8 operands and inner dimension d <= 65536, |sum A[i,t]*B[t,j]| <= 2^30 < (p-1)/2,
// so no honest integer matrix product ever wraps modulo p.
const (
	FieldModulus int64 = 2147483647
	MaxDimension int   = 65536
)

// ModP returns the canonical representative of x in [0, FieldModulus-1].
func ModP(x int64) int64 {
	r := x % FieldModulus
	if r < 0 {
		r += FieldModulus
	}
	return r
}

// ExactIntGEMM computes the exact whole-K integer matrix product C = A * B
// with zero intermediate floating-point conversion or rounding.
func ExactIntGEMM(a, b *Int8Matrix) (*Int64Matrix, error) {
	if a == nil || b == nil {
		return nil, fmt.Errorf("nil input matrix")
	}
	if a.Rows <= 0 || a.Cols <= 0 || b.Rows <= 0 || b.Cols <= 0 {
		return nil, fmt.Errorf("invalid non-positive dimensions: (%d,%d) x (%d,%d)", a.Rows, a.Cols, b.Rows, b.Cols)
	}
	if a.Cols != b.Rows {
		return nil, fmt.Errorf("dimension mismatch: A is %dx%d, B is %dx%d", a.Rows, a.Cols, b.Rows, b.Cols)
	}
	if a.Rows > MaxDimension || a.Cols > MaxDimension || b.Cols > MaxDimension {
		return nil, fmt.Errorf("dimensions exceed MaxDimension=%d", MaxDimension)
	}

	m, d, n := a.Rows, a.Cols, b.Cols
	c := NewInt64Matrix(m, n)
	aData := a.Data
	bData := b.Data
	cData := c.Data

	// Cache-friendly i-t-j traversal; exact integer addition is strictly associative.
	for i := 0; i < m; i++ {
		cRow := cData[i*n : (i+1)*n]
		aRow := aData[i*d : (i+1)*d]
		for t := 0; t < d; t++ {
			av := int64(aRow[t])
			if av == 0 {
				continue
			}
			bRow := bData[t*n : (t+1)*n]
			for j := 0; j < n; j++ {
				cRow[j] += av * int64(bRow[j])
			}
		}
	}
	return c, nil
}

// MatVecInt8ModP computes y = M * r (mod p) for int8 matrix M and vector r in [0, p-1]^cols.
// When binaryMode is true (r[j] in {0, 1}), skips multiplications for speed while yielding
// the exact bit-identical canonical representative in [0, p-1].
func MatVecInt8ModP(m *Int8Matrix, r []int64, binaryMode bool) []int64 {
	rows, cols := m.Rows, m.Cols
	out := make([]int64, rows)
	data := m.Data
	if binaryMode {
		for i := 0; i < rows; i++ {
			row := data[i*cols : (i+1)*cols]
			var acc int64
			for j := 0; j < cols; j++ {
				if r[j] != 0 {
					acc += int64(row[j])
				}
			}
			out[i] = ModP(acc)
		}
		return out
	}

	for i := 0; i < rows; i++ {
		row := data[i*cols : (i+1)*cols]
		var acc int64
		for j := 0; j < cols; j++ {
			acc += int64(row[j]) * r[j]
			// |row[j]| <= 128, r[j] < 2^31, so each product < 2^38.
			// Reducing every iteration keeps acc strictly bounded and overflow-free.
			acc %= FieldModulus
		}
		if acc < 0 {
			acc += FieldModulus
		}
		out[i] = acc
	}
	return out
}

// MatVecInt64ModP computes y = M * r (mod p) for int64 matrix M and vector r in [0, p-1]^cols.
// Safely reduces arbitrary (potentially adversarially corrupted) int64 entries modulo p before
// multiplying to guarantee zero signed int64 overflow.
func MatVecInt64ModP(m *Int64Matrix, r []int64, binaryMode bool) []int64 {
	rows, cols := m.Rows, m.Cols
	out := make([]int64, rows)
	data := m.Data
	if binaryMode {
		for i := 0; i < rows; i++ {
			row := data[i*cols : (i+1)*cols]
			var acc int64
			for j := 0; j < cols; j++ {
				if r[j] != 0 {
					acc += ModP(row[j])
					if acc >= FieldModulus {
						acc -= FieldModulus
					}
				}
			}
			out[i] = acc
		}
		return out
	}

	for i := 0; i < rows; i++ {
		row := data[i*cols : (i+1)*cols]
		var acc int64
		for j := 0; j < cols; j++ {
			mv := ModP(row[j])
			acc = (acc + mv*r[j]) % FieldModulus
		}
		out[i] = acc
	}
	return out
}
