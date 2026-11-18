// Package cbc holds the initialization-vector handling shared by the AES and
// TDEA data encryption functions.
package cbc

// IV returns a new blockSize-byte initialization vector built from iv: all
// zeros when iv is nil or empty, iv followed by zeros when it is shorter than a
// block, and the first blockSize bytes when it is longer.
//
// The result is always a fresh slice. iv is never modified, so a caller's
// buffer is safe even when it has spare capacity, and cipher.NewCBCEncrypter
// and cipher.NewCBCDecrypter, which panic on any other length, always get
// exactly one block.
func IV(iv []byte, blockSize int) []byte {
	out := make([]byte, blockSize)
	copy(out, iv)
	return out
}
