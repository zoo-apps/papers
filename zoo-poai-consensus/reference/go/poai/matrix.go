// Copyright 2026 Zoo Labs Foundation & Hanzo Industries.
// SPDX-License-Identifier: Apache-2.0

package poai

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	domainMat   = "poai:v1:mat:"
	domainRow   = "poai:v1:row:"
	domainNode  = "poai:v1:node:"
	domainTrace = "poai:v1:trace:"
	domainVec   = "poai:v1:vec:"
)

// Int8Matrix is a row-major quantized signed 8-bit integer matrix.
type Int8Matrix struct {
	Rows int
	Cols int
	Data []int8
}

// Int64Matrix is a row-major exact integer matrix (output of whole-K GEMM).
type Int64Matrix struct {
	Rows int
	Cols int
	Data []int64
}

// NewInt8Matrix allocates a zeroed Rows x Cols int8 matrix.
func NewInt8Matrix(rows, cols int) *Int8Matrix {
	return &Int8Matrix{
		Rows: rows,
		Cols: cols,
		Data: make([]int8, rows*cols),
	}
}

// NewInt64Matrix allocates a zeroed Rows x Cols int64 matrix.
func NewInt64Matrix(rows, cols int) *Int64Matrix {
	return &Int64Matrix{
		Rows: rows,
		Cols: cols,
		Data: make([]int64, rows*cols),
	}
}

// Clone returns a deep copy of an Int64Matrix.
func (m *Int64Matrix) Clone() *Int64Matrix {
	cp := make([]int64, len(m.Data))
	copy(cp, m.Data)
	return &Int64Matrix{Rows: m.Rows, Cols: m.Cols, Data: cp}
}

// Clone returns a deep copy of an Int8Matrix.
func (m *Int8Matrix) Clone() *Int8Matrix {
	cp := make([]int8, len(m.Data))
	copy(cp, m.Data)
	return &Int8Matrix{Rows: m.Rows, Cols: m.Cols, Data: cp}
}

// Int8MatrixSHA256 computes SHA-256 over the canonical flat encoding of an int8 matrix.
func Int8MatrixSHA256(m *Int8Matrix, role byte) [32]byte {
	h := sha256.New()
	var hdr [12 + 1 + 1 + 4 + 4]byte
	copy(hdr[0:12], domainMat)
	hdr[12] = role
	hdr[13] = 1 // int8 width = 1 byte
	binary.LittleEndian.PutUint32(hdr[14:18], uint32(m.Rows))
	binary.LittleEndian.PutUint32(hdr[18:22], uint32(m.Cols))
	h.Write(hdr[:])

	buf := make([]byte, len(m.Data))
	for i, v := range m.Data {
		buf[i] = byte(v)
	}
	h.Write(buf)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Int64MatrixSHA256 computes SHA-256 over the canonical flat encoding of an int64 matrix.
func Int64MatrixSHA256(m *Int64Matrix, role byte) [32]byte {
	h := sha256.New()
	var hdr [12 + 1 + 1 + 4 + 4]byte
	copy(hdr[0:12], domainMat)
	hdr[12] = role
	hdr[13] = 8 // int64 width = 8 bytes
	binary.LittleEndian.PutUint32(hdr[14:18], uint32(m.Rows))
	binary.LittleEndian.PutUint32(hdr[18:22], uint32(m.Cols))
	h.Write(hdr[:])

	rowBuf := make([]byte, m.Cols*8)
	for r := 0; r < m.Rows; r++ {
		row := m.Data[r*m.Cols : (r+1)*m.Cols]
		for c, v := range row {
			binary.LittleEndian.PutUint64(rowBuf[c*8:(c+1)*8], uint64(v))
		}
		h.Write(rowBuf)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Int8MatrixMerkleRoot computes the canonical binary Merkle root of row digests for an int8 matrix.
func Int8MatrixMerkleRoot(m *Int8Matrix, role byte) [32]byte {
	leaves := make([][32]byte, m.Rows)
	rowBuf := make([]byte, m.Cols)
	var prefix [12 + 1 + 4 + 4]byte
	copy(prefix[0:12], domainRow)
	prefix[12] = role
	binary.LittleEndian.PutUint32(prefix[17:21], uint32(m.Cols))

	for r := 0; r < m.Rows; r++ {
		binary.LittleEndian.PutUint32(prefix[13:17], uint32(r))
		row := m.Data[r*m.Cols : (r+1)*m.Cols]
		for c, v := range row {
			rowBuf[c] = byte(v)
		}
		h := sha256.New()
		h.Write(prefix[:])
		h.Write(rowBuf)
		copy(leaves[r][:], h.Sum(nil))
	}
	return MerkleRoot(leaves)
}

// Int64MatrixMerkleRoot computes the canonical binary Merkle root of row digests for an int64 matrix.
func Int64MatrixMerkleRoot(m *Int64Matrix, role byte) [32]byte {
	leaves := make([][32]byte, m.Rows)
	rowBuf := make([]byte, m.Cols*8)
	var prefix [12 + 1 + 4 + 4]byte
	copy(prefix[0:12], domainRow)
	prefix[12] = role
	binary.LittleEndian.PutUint32(prefix[17:21], uint32(m.Cols))

	for r := 0; r < m.Rows; r++ {
		binary.LittleEndian.PutUint32(prefix[13:17], uint32(r))
		row := m.Data[r*m.Cols : (r+1)*m.Cols]
		for c, v := range row {
			binary.LittleEndian.PutUint64(rowBuf[c*8:(c+1)*8], uint64(v))
		}
		h := sha256.New()
		h.Write(prefix[:])
		h.Write(rowBuf)
		copy(leaves[r][:], h.Sum(nil))
	}
	return MerkleRoot(leaves)
}

// MerkleRoot computes a domain-separated binary SHA-256 Merkle root.
// Odd levels duplicate the last node. Empty leaf slice returns SHA-256("poai:v1:node:empty").
func MerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return sha256.Sum256([]byte("poai:v1:node:empty"))
	}
	level := make([][32]byte, len(leaves))
	copy(level, leaves)
	var buf [13 + 32 + 32]byte
	copy(buf[0:13], domainNode)
	for len(level) > 1 {
		nextLen := (len(level) + 1) / 2
		next := make([][32]byte, nextLen)
		for i := 0; i < nextLen; i++ {
			left := level[2*i]
			right := left
			if 2*i+1 < len(level) {
				right = level[2*i+1]
			}
			copy(buf[13:45], left[:])
			copy(buf[45:77], right[:])
			next[i] = sha256.Sum256(buf[:])
		}
		level = next
	}
	return level[0]
}

// ActivationTraceRoot binds the three matrix row-Merkle roots into a single commitment.
func ActivationTraceRoot(aRoot, bRoot, cRoot [32]byte) [32]byte {
	var buf [14 + 32 + 32 + 32]byte
	copy(buf[0:14], domainTrace)
	copy(buf[14:46], aRoot[:])
	copy(buf[46:78], bRoot[:])
	copy(buf[78:110], cRoot[:])
	return sha256.Sum256(buf[:])
}

// VecSHA256 computes SHA-256 over the canonical encoding of a field-element vector.
func VecSHA256(v []int64) [32]byte {
	h := sha256.New()
	var hdr [12 + 4]byte
	copy(hdr[0:12], domainVec)
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(v)))
	h.Write(hdr[:])
	buf := make([]byte, len(v)*8)
	for i, val := range v {
		binary.LittleEndian.PutUint64(buf[i*8:(i+1)*8], uint64(val))
	}
	h.Write(buf)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MatricesEqualInt64 checks exact entrywise equality of two Int64Matrix values.
func MatricesEqualInt64(a, b *Int64Matrix) (bool, error) {
	if a == nil || b == nil {
		return false, fmt.Errorf("nil matrix")
	}
	if a.Rows != b.Rows || a.Cols != b.Cols {
		return false, nil
	}
	for i := range a.Data {
		if a.Data[i] != b.Data[i] {
			return false, nil
		}
	}
	return true, nil
}
