// Package memzero clears buffers that held key material.
//
// DUKPT derives a chain of keys (intermediate derivation keys, the transaction
// key, and the PIN, MAC and data working keys). Every one of them is a secret,
// and PCI PIN and similar key-management requirements expect a key to be
// cleared from memory as soon as it is no longer needed, rather than left on
// the heap until the garbage collector reuses the memory.
//
// What this does and does not guarantee: it overwrites the buffer it is given.
// It cannot reach copies made elsewhere, such as the expanded key schedule
// inside a crypto/cipher.Block, an HMAC's padded keys, or a string, because Go
// offers no way to clear those.
package memzero

import "runtime"

// Bytes overwrites every byte of b with zero.
//
// It is not inlined, and keeps b reachable until the write is done, so the
// compiler cannot treat the clear as a dead store to a buffer that is about to
// go out of scope.
//
//go:noinline
func Bytes(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}
